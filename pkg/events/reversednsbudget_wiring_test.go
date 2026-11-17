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

package events

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// ptrCountingResolver serves lab's answers and counts the PTR queries.
func ptrCountingResolver(t *testing.T, lab *dnsLab, ptrs *atomic.Int32) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	started := make(chan struct{})
	srv := &dns.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			if r.Question[0].Qtype == dns.TypePTR {
				ptrs.Add(1)
			}
			lab.answer(w, r)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown(); _ = pc.Close() })
	addr := pc.LocalAddr().String()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", addr)
	}}
}

func allowedSYN(t *testing.T, fw *mockFirewallUpdater, dstIP string) {
	t.Helper()
	auditLogger, err := NewAuditLogger(filepath.Join(t.TempDir(), "audit.jsonl"), false)
	require.NoError(t, err)
	defer auditLogger.Close()
	processEvent(makeBpfEvent(BpfBlockedEvent{
		IpVersion: 4, IpProto: unix.IPPROTO_TCP, Allowed: 1,
		SrcIp: ipv4ToUint32("10.0.0.1"), DstIp: ipv4ToUint32(dstIP), SrcPort: 54321, DstPort: 443,
	}), githubPolicy(t), nil, auditLogger, fw, newTestLogger())
}

// The budget gates processEvent's lazy lookups: two per /24 for denials, a
// capped address stays unlooked-up however often it is denied, a local
// address isn't counted, and an allowed connection's lookup isn't budgeted.
func TestProcessEvent_ReverseLookupBudget(t *testing.T) {
	var ptrs atomic.Int32
	lab := &dnsLab{ptr: []string{"unrelated.example.net"}}
	useReverseDNS(t, ptrCountingResolver(t, lab, &ptrs))
	cm := githubPolicy(t)
	fw := &mockFirewallUpdater{}

	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		denySYNs(t, cm, fw, ip, 1)
	}
	assert.EqualValues(t, 2, ptrs.Load(), "two denied lookups per /24")
	denySYNs(t, cm, fw, "192.0.2.3", 3)
	assert.EqualValues(t, 2, ptrs.Load(), "a capped address is final")
	for _, ip := range []string{"10.96.0.1", "10.96.0.2", "10.96.0.3"} {
		denySYNs(t, cm, fw, ip, 1)
	}
	assert.EqualValues(t, 5, ptrs.Load(), "local addresses aren't counted")
	allowedSYN(t, fw, "192.0.2.4")
	assert.EqualValues(t, 6, ptrs.Load(), "an allowed connection's lookup isn't budgeted")
}
