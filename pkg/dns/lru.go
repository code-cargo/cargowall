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
	"container/list"
	"sync"
	"time"
)

// lruCache is a generic thread-safe LRU cache with optional TTL support.
// All operations are O(1). Expired entries are lazily removed on Get.
type lruCache[K comparable, V any] struct {
	mu       sync.Mutex
	capacity int
	items    map[K]*list.Element
	order    *list.List // front = most recently used
}

type lruEntry[K comparable, V any] struct {
	key    K
	value  V
	expiry time.Time // zero value means no expiry
}

// newLRUCache creates a new LRU cache with the given maximum capacity.
func newLRUCache[K comparable, V any](capacity int) *lruCache[K, V] {
	return &lruCache[K, V]{
		capacity: capacity,
		items:    make(map[K]*list.Element, capacity),
		order:    list.New(),
	}
}

// Get returns the value for key and moves it to the front of the LRU list.
// Returns false if the key is missing or expired.
func (c *lruCache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		var zero V
		return zero, false
	}

	e := elem.Value.(*lruEntry[K, V])

	// Lazy TTL expiry
	if !e.expiry.IsZero() && time.Now().After(e.expiry) {
		c.order.Remove(elem)
		delete(c.items, key)
		var zero V
		return zero, false
	}

	c.order.MoveToFront(elem)
	return e.value, true
}

// Put adds or updates a key-value pair. If ttl is 0, the entry never expires.
// Evicts the least recently used entry if the cache is at capacity.
func (c *lruCache[K, V]) Put(key K, value V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var expiry time.Time
	if ttl > 0 {
		expiry = time.Now().Add(ttl)
	}

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		e := elem.Value.(*lruEntry[K, V])
		e.value = value
		e.expiry = expiry
		return
	}

	// Evict LRU tail if at capacity
	if c.order.Len() >= c.capacity {
		tail := c.order.Back()
		if tail != nil {
			c.order.Remove(tail)
			delete(c.items, tail.Value.(*lruEntry[K, V]).key)
		}
	}

	elem := c.order.PushFront(&lruEntry[K, V]{
		key:    key,
		value:  value,
		expiry: expiry,
	})
	c.items[key] = elem
}

// Delete removes a key from the cache.
func (c *lruCache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.Remove(elem)
		delete(c.items, key)
	}
}

// Len returns the number of entries in the cache (including expired ones
// that have not yet been lazily evicted).
func (c *lruCache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
