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

package cmd

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
)

// edgeAddrs are the addresses edge.cdn.example.net resolves to.
var edgeAddrs = []string{"203.0.113.5", "203.0.113.6"}

// ptrServer is a Go resolver for a local DNS server that names every
// address edge.cdn.example.net by PTR, and resolves that name to edgeAddrs,
// so the PTR name is forward-confirmed for them.
func ptrServer(t *testing.T) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	started := make(chan struct{})
	srv := &dns.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.RecursionAvailable = true
			q := r.Question[0]
			switch {
			case q.Qtype == dns.TypePTR:
				m.Answer = append(m.Answer, &dns.PTR{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
					Ptr: "edge.cdn.example.net.",
				})
			case q.Qtype == dns.TypeA && q.Name == "edge.cdn.example.net.":
				for _, a := range edgeAddrs {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP(a),
					})
				}
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown(); _ = pc.Close() })

	addr := pc.LocalAddr().String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

// The startup round names existing connections' peers by PTR, but a peer
// the proxy already named, the policy's name rules match, keeps that name.
func TestReverseDNSExistingConnections_KeepsAForwardName(t *testing.T) {
	cm := config.NewConfigManager()
	require.NoError(t, cm.LoadConfigFromRules([]config.Rule{
		{Type: config.RuleTypeHostname, Value: "cdn.example.net", Action: config.ActionAllow},
	}, config.ActionDeny))
	cm.UpdateDNSMapping("denied.example.com", "203.0.113.5")
	https := []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}
	conns := existingConns{"203.0.113.5": https, "203.0.113.6": https}

	reverseDNSExistingConnections(context.Background(), conns, cm, ptrServer(t), quietLogger())

	assert.Equal(t, "denied.example.com", cm.LookupHostnameByIP("203.0.113.5"), "the forward name is kept")
	assert.Equal(t, "edge.cdn.example.net", cm.LookupHostnameByIP("203.0.113.6"), "an unnamed peer takes its PTR name")
}
