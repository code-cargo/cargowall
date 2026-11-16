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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamReverseResolver resolves at the upstream it is given, not
// through the system resolver: a reverse lookup reaches that server and
// returns its name. Marking the socket needs CAP_NET_ADMIN, so the test
// runs as root.
func TestNewUpstreamReverseResolver_ReachesTheUpstream(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("marking a socket needs CAP_NET_ADMIN")
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	started := make(chan struct{})
	var mu sync.Mutex
	var asked []dns.Question
	srv := &dns.Server{
		PacketConn:        pc,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			mu.Lock()
			asked = append(asked, r.Question[0])
			mu.Unlock()
			m := new(dns.Msg)
			m.SetReply(r)
			if r.Question[0].Qtype == dns.TypePTR {
				m.Answer = []dns.RR{&dns.PTR{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
					Ptr: "peer.example.net.",
				}}
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown(); _ = pc.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	names, err := newUpstreamReverseResolver(pc.LocalAddr().String()).LookupAddr(ctx, "192.0.2.7")
	require.NoError(t, err)
	assert.Equal(t, []string{"peer.example.net."}, names)
	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, asked)
	assert.Equal(t, "7.2.0.192.in-addr.arpa.", asked[0].Name)
}
