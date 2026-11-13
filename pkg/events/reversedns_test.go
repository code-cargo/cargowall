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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/config"
)

// dnsLab is a local DNS server for the event path's lookups. It answers PTR
// queries for any address with ptr, and A queries from forward (name ->
// address); any other name does not exist. A PTR record can claim any name,
// but only the claimed domain's owner decides where that name resolves.
// dropFirstA leaves the first A query unanswered, as a lost packet does.
type dnsLab struct {
	ptr        []string
	forward    map[string]string
	dropFirstA bool
	aQueries   atomic.Int32
}

// resolver starts the server and returns a Go resolver that uses it.
func (l *dnsLab) resolver(t *testing.T) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	started := make(chan struct{})
	srv := &dns.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(started) },
		Handler:           dns.HandlerFunc(l.answer),
	}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown(); _ = pc.Close() })

	serverAddr := pc.LocalAddr().String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", serverAddr)
		},
	}
}

func (l *dnsLab) answer(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	q := r.Question[0]
	addr, known := l.forward[strings.TrimSuffix(strings.ToLower(q.Name), ".")]
	switch {
	case q.Qtype == dns.TypePTR:
		for _, name := range l.ptr {
			m.Answer = append(m.Answer, &dns.PTR{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
				Ptr: dns.Fqdn(name),
			})
		}
	case q.Qtype == dns.TypeA:
		if l.aQueries.Add(1) == 1 && l.dropFirstA {
			return
		}
		if known {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(addr),
			})
		} else {
			m.Rcode = dns.RcodeNameError
		}
	case known:
		// The name exists, without a record of this type.
	default:
		m.Rcode = dns.RcodeNameError
	}
	_ = w.WriteMsg(m)
}

// useReverseDNS points the event path's reverse lookups at r, with an empty
// lookup cache and retry count, restoring the resolver when the test ends.
func useReverseDNS(t *testing.T, r *net.Resolver) {
	t.Helper()
	prev := reverseDNSResolver
	reverseDNSResolver = r
	reverseDNSMu.Lock()
	reverseDNSCache = make(map[string]time.Time)
	reverseDNSRetried = make(map[string]int)
	reverseDNSMu.Unlock()
	t.Cleanup(func() { reverseDNSResolver = prev })
}

// denySYNs reports n denied SYNs to dstIP:443, the client's first attempt and
// its retransmits, and returns their audit events.
func denySYNs(t *testing.T, cm *config.Manager, fw *mockFirewallUpdater, dstIP string, n int) []AuditEvent {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLogger, err := NewAuditLogger(auditPath, false)
	require.NoError(t, err)
	defer auditLogger.Close()
	for range n {
		processEvent(makeBpfEvent(BpfBlockedEvent{
			IpVersion: 4, IpProto: unix.IPPROTO_TCP,
			SrcIp: ipv4ToUint32("10.0.0.1"), DstIp: ipv4ToUint32(dstIP), SrcPort: 54321, DstPort: 443,
		}), cm, nil, auditLogger, fw, newTestLogger())
	}
	return readAuditEvents(t, auditPath)
}

// githubPolicy allows github.com on tcp/443, as the GitHub Actions preset's
// service-host rule does: the kind of rule a forged PTR record aims at.
func githubPolicy(t *testing.T) *config.Manager {
	t.Helper()
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{{
		Type:   config.RuleTypeHostname,
		Value:  "github.com",
		Action: config.ActionAllow,
		Ports:  []config.Port{{Port: 443, Protocol: config.ProtocolTCP}},
	}}, config.ActionDeny))
	return cm
}

// A PTR record is the address owner's claim, and can name any host. One
// naming a subdomain of an allowed host must neither late-allow nor label a
// denied connection to an address that host's own DNS never gave, or anyone
// who controls a reverse zone could open the firewall to their own server.
func TestProcessEvent_ForgedPTRDoesNotLateAllow(t *testing.T) {
	const attackerIP = "203.0.113.66"
	cases := map[string]map[string]string{
		"the claimed name does not exist":     nil,
		"the claimed name resolves elsewhere": {"exfil.github.com": "140.82.112.3"},
	}
	for name, forward := range cases {
		t.Run(name, func(t *testing.T) {
			useReverseDNS(t, (&dnsLab{ptr: []string{"exfil.github.com"}, forward: forward}).resolver(t))
			cm := githubPolicy(t)
			fw := &mockFirewallUpdater{}

			events := denySYNs(t, cm, fw, attackerIP, 3)

			require.Len(t, events, 3)
			for _, ev := range events {
				assert.Equal(t, EventConnectionBlocked, ev.EventType)
				assert.Empty(t, ev.DstHostname, "the forged name labels nothing")
				assert.Empty(t, ev.MatchedRule)
			}
			assert.Empty(t, fw.addedIPs, "nothing opened under the forged name")
			assert.Empty(t, cm.LookupHostnameByIP(attackerIP), "the forged name is not cached")
		})
	}
}

// A reverse name whose forward lookup leads back to the IP still names it,
// and late-allows it under the rule it matches: policies allow remote
// builders by their reverse names.
func TestProcessEvent_ConfirmedPTRLateAllows(t *testing.T) {
	useReverseDNS(t, (&dnsLab{
		ptr:     []string{"ec2-198-51-100-7.compute-1.amazonaws.com"},
		forward: map[string]string{"ec2-198-51-100-7.compute-1.amazonaws.com": builderIP},
	}).resolver(t))
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}

	events := denySYNs(t, cm, fw, builderIP, 1)

	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionLateAllowed, events[0].EventType)
	assert.Equal(t, "*.compute-1.amazonaws.com", events[0].MatchedRule)
	assert.Equal(t, "ec2-198-51-100-7.compute-1.amazonaws.com", events[0].DstHostname)
	require.Len(t, fw.addedIPs, 1)
	assert.True(t, fw.addedIPs[0].ip.Equal(net.ParseIP(builderIP)))
}

// builderIP is a remote builder's address, named by its EC2 reverse name.
const builderIP = "198.51.100.7"

// builderPolicy allows remote builders by their reverse names on tcp/443.
func builderPolicy(t *testing.T) *config.Manager {
	t.Helper()
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{{
		Type:   config.RuleTypeHostname,
		Value:  "*.compute-1.amazonaws.com",
		Action: config.ActionAllow,
		Ports:  []config.Port{{Port: 443, Protocol: config.ProtocolTCP}},
	}}, config.ActionDeny))
	return cm
}

// A PTR answer can carry several names. A forged one first must not stop a
// genuine one after it from naming the IP, and the genuine one is matched in
// lowercase, whatever case it came back in.
func TestProcessEvent_GenuinePTRNameAfterAForgedOneLateAllows(t *testing.T) {
	const ip = "198.51.100.11"
	useReverseDNS(t, (&dnsLab{
		ptr:     []string{"exfil.github.com", "Ok11.GitHub.Com"},
		forward: map[string]string{"ok11.github.com": ip},
	}).resolver(t))
	cm := githubPolicy(t)
	fw := &mockFirewallUpdater{}

	events := denySYNs(t, cm, fw, ip, 1)

	require.Len(t, events, 1)
	assert.Equal(t, EventConnectionLateAllowed, events[0].EventType)
	assert.Equal(t, "github.com", events[0].MatchedRule)
	require.Len(t, fw.addedIPs, 1)
	assert.True(t, fw.addedIPs[0].ip.Equal(net.ParseIP(ip)))
}

// A reverse name no rule allows can't change a verdict, so it is neither
// confirmed nor used as a label: no forward query goes to a zone the
// destination's owner chose, and none reaches the proxy's filter, which would
// refuse it and record it as the job's query.
func TestProcessEvent_PTRNameNoRuleAllowsIsNotLookedUp(t *testing.T) {
	lab := &dnsLab{ptr: []string{"server9.hosting.example"}}
	useReverseDNS(t, lab.resolver(t))
	cm := githubPolicy(t)
	fw := &mockFirewallUpdater{}

	events := denySYNs(t, cm, fw, "203.0.113.9", 2)

	require.Len(t, events, 2)
	for _, ev := range events {
		assert.Equal(t, EventConnectionBlocked, ev.EventType)
		assert.Empty(t, ev.DstHostname, "a name no rule allows labels nothing")
	}
	assert.Zero(t, lab.aQueries.Load(), "no forward query for a name no rule allows")
	assert.Empty(t, fw.addedIPs)
}

// A confirmation that times out says nothing about the reverse name. The IP
// is looked up again at its next event, the client's SYN retransmit, and the
// name, once confirmed, late-allows: one lost packet must not block a
// destination its reverse name allows for the rest of the run.
func TestProcessEvent_ConfirmationTimeoutRetriesThenLateAllows(t *testing.T) {
	lab := &dnsLab{
		ptr:        []string{"ec2-198-51-100-7.compute-1.amazonaws.com"},
		forward:    map[string]string{"ec2-198-51-100-7.compute-1.amazonaws.com": builderIP},
		dropFirstA: true,
	}
	useReverseDNS(t, lab.resolver(t))
	cm := builderPolicy(t)
	fw := &mockFirewallUpdater{}

	events := denySYNs(t, cm, fw, builderIP, 2)

	require.Len(t, events, 2)
	assert.Equal(t, EventConnectionBlocked, events[0].EventType, "the dropped confirmation names nothing yet")
	assert.Equal(t, EventConnectionLateAllowed, events[1].EventType, "the retransmit's lookup confirms the name")
	assert.Equal(t, "*.compute-1.amazonaws.com", events[1].MatchedRule)
	assert.Equal(t, int32(2), lab.aQueries.Load())
}
