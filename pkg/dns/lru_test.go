//   Copyright 2026 BoxBuild Inc DBA CodeCargo
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

//go:build linux

package dns

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// peekExpiry returns the expiry recorded for key and whether the key is
// present, without touching LRU order or applying lazy expiration. A zero
// expiry means the entry never expires. Test-only introspection so tests can
// assert the stored TTL (the public API only exposes presence via Get).
func (c *lruCache[K, V]) peekExpiry(key K) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.items[key]
	if !ok {
		return time.Time{}, false
	}
	return elem.Value.(*lruEntry[K, V]).expiry, true
}

// Basic round-trip: Put → Get returns the stored value.
func TestLRUCache_Basic(t *testing.T) {
	c := newLRUCache[string, int](10)
	c.Put("a", 1, 0)

	got, ok := c.Get("a")
	require.True(t, ok)
	assert.Equal(t, 1, got)
}

// Missing key returns zero value + false.
func TestLRUCache_GetMissing(t *testing.T) {
	c := newLRUCache[string, int](10)
	got, ok := c.Get("never-put")
	assert.False(t, ok)
	assert.Equal(t, 0, got, "missing key must return zero value of V")
}

// ttl > 0 expires the entry; Get after expiry returns false AND lazily
// removes it from the underlying store.
func TestLRUCache_TTLExpiry(t *testing.T) {
	c := newLRUCache[string, string](10)
	c.Put("ephemeral", "value", 10*time.Millisecond)
	assert.Equal(t, 1, c.Len(), "entry present before expiry")

	time.Sleep(20 * time.Millisecond)

	_, ok := c.Get("ephemeral")
	assert.False(t, ok, "expired entry must report missing")
	assert.Equal(t, 0, c.Len(), "expired entry must be lazily removed on Get")
}

// ttl == 0 disables expiration entirely. Pin so a future change to "treat
// 0 as immediate expiry" is a deliberate decision.
func TestLRUCache_TTLZeroNeverExpires(t *testing.T) {
	c := newLRUCache[string, string](10)
	c.Put("permanent", "value", 0)

	// Sleep past what any reasonable TTL would have been.
	time.Sleep(20 * time.Millisecond)

	got, ok := c.Get("permanent")
	require.True(t, ok, "ttl=0 entry must persist indefinitely")
	assert.Equal(t, "value", got)
}

// Putting an existing key updates the value AND the expiry, and moves
// the entry to the front of the LRU list. Pin the in-place update path
// (line 86-91 in lru.go).
func TestLRUCache_UpdateExistingKey(t *testing.T) {
	c := newLRUCache[string, string](10)
	c.Put("k", "v1", 0)
	c.Put("k", "v2", 0)

	got, ok := c.Get("k")
	require.True(t, ok)
	assert.Equal(t, "v2", got, "update must replace value")
	assert.Equal(t, 1, c.Len(), "update must not increment count")
}

// Update-existing also refreshes the expiry. Put with a short TTL, then
// Put again with ttl=0; the entry should persist past the original expiry.
func TestLRUCache_UpdateExistingKeyRefreshesExpiry(t *testing.T) {
	c := newLRUCache[string, string](10)
	c.Put("k", "v1", 10*time.Millisecond)
	c.Put("k", "v2", 0) // refresh: no expiry

	time.Sleep(20 * time.Millisecond)
	got, ok := c.Get("k")
	require.True(t, ok, "update with ttl=0 must clear prior expiry")
	assert.Equal(t, "v2", got)
}

// Eviction at capacity: insertion that exceeds capacity removes the
// least-recently-used entry. Verify the LRU tail (oldest by access time)
// is the one evicted.
func TestLRUCache_EvictsLRU(t *testing.T) {
	c := newLRUCache[string, int](3)
	c.Put("a", 1, 0)
	c.Put("b", 2, 0)
	c.Put("c", 3, 0)
	// All three present.
	assert.Equal(t, 3, c.Len())

	// Touch "a" so it becomes most-recently-used; "b" becomes LRU.
	_, _ = c.Get("a")

	// Insert a 4th key — should evict "b" (LRU), not "a".
	c.Put("d", 4, 0)
	assert.Equal(t, 3, c.Len())

	if _, ok := c.Get("a"); !ok {
		t.Errorf("a should survive eviction (recently used)")
	}
	if _, ok := c.Get("b"); ok {
		t.Errorf("b should have been evicted (was LRU)")
	}
	if _, ok := c.Get("c"); !ok {
		t.Errorf("c should survive eviction")
	}
	if _, ok := c.Get("d"); !ok {
		t.Errorf("d should be present (just inserted)")
	}
}

// Delete removes the entry and Get reports missing.
func TestLRUCache_Delete(t *testing.T) {
	c := newLRUCache[string, int](10)
	c.Put("a", 1, 0)
	assert.Equal(t, 1, c.Len())

	c.Delete("a")
	assert.Equal(t, 0, c.Len())

	_, ok := c.Get("a")
	assert.False(t, ok, "deleted entry must report missing")
}

// Delete on a missing key is a no-op (no panic, no state change).
func TestLRUCache_DeleteMissingNoOp(t *testing.T) {
	c := newLRUCache[string, int](10)
	c.Put("a", 1, 0)

	c.Delete("never-present") // must not panic
	assert.Equal(t, 1, c.Len(), "Delete on missing key must not affect other entries")

	_, ok := c.Get("a")
	assert.True(t, ok)
}

// Len reports the count including entries that have expired but haven't
// been lazily evicted yet. Pin this comment-documented behavior.
func TestLRUCache_LenIncludesNotYetEvictedExpired(t *testing.T) {
	c := newLRUCache[string, string](10)
	c.Put("a", "v", 10*time.Millisecond)
	c.Put("b", "v", 0) // never expires
	assert.Equal(t, 2, c.Len())

	time.Sleep(20 * time.Millisecond)

	// "a" has expired in the time sense, but has NOT been touched, so it
	// still occupies a slot until the next Get/Put lazily evicts.
	assert.Equal(t, 2, c.Len(), "Len includes expired-but-not-yet-evicted entries")

	// Now Get "a" — lazy eviction kicks in.
	_, ok := c.Get("a")
	assert.False(t, ok)
	assert.Equal(t, 1, c.Len(), "lazy eviction on Get removes expired entry")
}

// Concurrent Get/Put must not race. Run under `go test -race` to catch any
// missed locking.
func TestLRUCache_ConcurrentAccess(t *testing.T) {
	c := newLRUCache[int, int](100)
	const (
		writers      = 4
		readers      = 8
		opsPerWriter = 500
		opsPerReader = 1000
		keySpace     = 50
	)

	var wg sync.WaitGroup
	wg.Add(writers + readers)

	for w := 0; w < writers; w++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < opsPerWriter; i++ {
				key := (seed + i) % keySpace
				c.Put(key, i, 0)
			}
		}(w)
	}
	for r := 0; r < readers; r++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < opsPerReader; i++ {
				key := (seed + i) % keySpace
				_, _ = c.Get(key)
				if i%10 == 0 {
					c.Delete(key)
				}
			}
		}(r)
	}
	wg.Wait()

	// Sanity: cache is still functional after the race.
	c.Put(-1, 999, 0)
	got, ok := c.Get(-1)
	require.True(t, ok)
	assert.Equal(t, 999, got)
}
