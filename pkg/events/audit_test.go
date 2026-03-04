//go:build linux

package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readAuditEvents(t *testing.T, path string) []AuditEvent {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	events := make([]AuditEvent, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var ev AuditEvent
		require.NoError(t, json.Unmarshal([]byte(line), &ev))
		events = append(events, ev)
	}
	return events
}

func TestAuditLogger_EnforceMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := NewAuditLogger(path, false)
	require.NoError(t, err)
	defer logger.Close()

	err = logger.LogConnectionBlocked("10.0.0.1", "93.184.216.34", "example.com", 443, "curl", 1234)
	require.NoError(t, err)

	events := readAuditEvents(t, path)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionBlocked, events[0].EventType)
	assert.True(t, events[0].Blocked)
	assert.False(t, events[0].WouldDeny)
	assert.Equal(t, "example.com", events[0].DstHostname)
	assert.Equal(t, uint16(443), events[0].DstPort)
	assert.Equal(t, "curl", events[0].Process)
	assert.Equal(t, uint32(1234), events[0].PID)
}

func TestAuditLogger_AuditMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := NewAuditLogger(path, true)
	require.NoError(t, err)
	defer logger.Close()

	err = logger.LogConnectionBlocked("10.0.0.1", "93.184.216.34", "example.com", 443, "curl", 1234)
	require.NoError(t, err)

	events := readAuditEvents(t, path)
	require.Len(t, events, 1)
	assert.False(t, events[0].Blocked)
	assert.True(t, events[0].WouldDeny)
}

func TestAuditLogger_AllowedEventDoesNotOverrideFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := NewAuditLogger(path, false)
	require.NoError(t, err)
	defer logger.Close()

	err = logger.LogConnectionAllowed("10.0.0.1", "93.184.216.34", "example.com", 443, "curl", 1)
	require.NoError(t, err)

	events := readAuditEvents(t, path)
	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionAllowed, events[0].EventType)
	// Allowed events should NOT have their flags overridden by enforce/audit mode
	assert.False(t, events[0].Blocked)
	assert.False(t, events[0].WouldDeny)
}

func TestAuditLogger_DNSBlocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := NewAuditLogger(path, false)
	require.NoError(t, err)
	defer logger.Close()

	err = logger.LogDNSBlocked("evil.com")
	require.NoError(t, err)

	events := readAuditEvents(t, path)
	require.Len(t, events, 1)
	assert.Equal(t, EventDNSBlocked, events[0].EventType)
	assert.Equal(t, "evil.com", events[0].DstHostname)
	assert.True(t, events[0].Blocked)
}

func TestAuditLogger_ExistingConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := NewAuditLogger(path, false)
	require.NoError(t, err)
	defer logger.Close()

	// Allowed existing connection
	err = logger.LogExistingConnection("1.2.3.4", "example.com", "hostname:example.com", true)
	require.NoError(t, err)

	// Blocked existing connection
	err = logger.LogExistingConnection("5.6.7.8", "bad.com", "hostname:bad.com", false)
	require.NoError(t, err)

	events := readAuditEvents(t, path)
	require.Len(t, events, 2)

	assert.Equal(t, EventExistingConnection, events[0].EventType)
	assert.False(t, events[0].Blocked)
	assert.False(t, events[0].WouldDeny)

	assert.Equal(t, EventExistingConnection, events[1].EventType)
	assert.True(t, events[1].Blocked)
	assert.True(t, events[1].WouldDeny)
}

func TestAuditLogger_ProtocolBlocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := NewAuditLogger(path, false)
	require.NoError(t, err)
	defer logger.Close()

	err = logger.LogProtocolBlocked("10.0.0.1", "10.0.0.2", "", "ICMP", "ping", 99)
	require.NoError(t, err)

	events := readAuditEvents(t, path)
	require.Len(t, events, 1)
	assert.Equal(t, EventProtocolBlocked, events[0].EventType)
	assert.Equal(t, "ICMP", events[0].Protocol)
	assert.True(t, events[0].Blocked)
}

func TestAuditLogger_CloseIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := NewAuditLogger(path, false)
	require.NoError(t, err)

	require.NoError(t, logger.Close())
	// Second close should be safe (nil file guard)
	require.NoError(t, logger.Close())
}

func TestAuditLogger_IsAuditMode(t *testing.T) {
	dir := t.TempDir()

	enforceLogger, err := NewAuditLogger(filepath.Join(dir, "enforce.jsonl"), false)
	require.NoError(t, err)
	defer enforceLogger.Close()
	assert.False(t, enforceLogger.IsAuditMode())

	auditLogger, err := NewAuditLogger(filepath.Join(dir, "audit.jsonl"), true)
	require.NoError(t, err)
	defer auditLogger.Close()
	assert.True(t, auditLogger.IsAuditMode())
}

func TestAuditLogger_InvalidPath(t *testing.T) {
	_, err := NewAuditLogger("/nonexistent/dir/audit.jsonl", false)
	assert.Error(t, err)
}
