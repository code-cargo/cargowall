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
	"errors"
	"fmt"
	rand "math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/code-cargo/cargowall/pkg/config"
	"github.com/code-cargo/cargowall/pkg/firewall"
)

// recordingFirewall is a firewall.Firewall that keeps what was written under
// which policy: the job's allows (AddIP) and each step policy's (AddPolicyIP).
type recordingFirewall struct {
	mu       sync.Mutex
	jobAllow map[string][]config.Port
	jobDeny  map[string]bool
	step     map[uint32]map[string][]config.Port
	stepErr  error
	stepAdd  chan struct{} // signalled on each step write, if set
	policy0  int           // AddPolicyIP calls naming the job's policy
}

func newRecordingFirewall() *recordingFirewall {
	return &recordingFirewall{
		jobAllow: map[string][]config.Port{},
		jobDeny:  map[string]bool{},
		step:     map[uint32]map[string][]config.Port{},
	}
}

func (f *recordingFirewall) SetDefaultAction(config.Action) error { return nil }

func (f *recordingFirewall) SetAuditMode(bool) error { return nil }

func (f *recordingFirewall) UpdateAllowlistTC(cm *config.Manager) error { return nil }

func (f *recordingFirewall) RemoveIP(net.IP) error { return nil }

func (f *recordingFirewall) stepIPs(policy uint32) map[string][]config.Port {
	return f.snapshot(policy)
}

func (f *recordingFirewall) AddIP(ip net.IP, action config.Action, ports []config.Port) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if action == config.ActionAllow {
		f.jobAllow[ip.String()] = config.UnionPorts(f.jobAllow[ip.String()], ports)
	} else {
		f.jobDeny[ip.String()] = true
	}
	return true, nil
}

func (f *recordingFirewall) AddPolicyIP(policy uint32, ip net.IP, ports []config.Port) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if policy == 0 {
		f.policy0++
		return false, errors.New("AddPolicyIP under the job's policy")
	}
	if f.stepErr != nil {
		return false, f.stepErr
	}
	if f.step[policy] == nil {
		f.step[policy] = map[string][]config.Port{}
	}
	prev, seen := f.step[policy][ip.String()]
	if seen {
		ports = config.UnionPorts(prev, ports)
	}
	f.step[policy][ip.String()] = ports
	if f.stepAdd != nil {
		f.stepAdd <- struct{}{}
	}
	return true, nil
}

func (f *recordingFirewall) snapshot(policy uint32) map[string][]config.Port {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string][]config.Port{}
	for ip, ps := range f.step[policy] {
		out[ip] = ps
	}
	return out
}

func (f *recordingFirewall) jobAllows(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.jobAllow[ip]
	return ok
}

var _ firewall.Firewall = (*recordingFirewall)(nil)

// discardWriter is a dns.ResponseWriter that drops the reply.
type discardWriter struct{ MockResponseWriter }

func (*discardWriter) WriteMsg(*dns.Msg) error { return nil }

func newStepTestServer(t *testing.T, cfg *config.Manager, fw firewall.Firewall) *Server {
	t.Helper()
	s := newTestServer(t, cfg, fw)
	s.steps = newStepTier()
	return s
}

// loadStepPolicy loads a JSON policy through LoadConfig, the loader that
// takes steps.
func loadStepPolicy(t *testing.T, cfg *config.Manager, policy string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(path, []byte(policy), 0o600))
	require.NoError(t, cfg.LoadConfig(path))
}

// answer serves resp for qname through handleDNSQuery, from the cache.
func answer(s *Server, qname string, resp *dns.Msg) {
	qname = dns.Fqdn(qname)
	resp = resp.Copy()
	resp.Question = []dns.Question{{Name: qname, Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	seedCachedResponse(s, qname, resp)
	q := new(dns.Msg)
	q.SetQuestion(qname, dns.TypeA)
	s.handleDNSQuery(&discardWriter{}, q)
}

func aResponse(qname string, ips ...string) *dns.Msg {
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess}}
	for _, ip := range ips {
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(ip),
		})
	}
	return msg
}

// The policy the writer tests share. Step "fetch" is policy 1, "deploy" 2.
const stepWritersPolicy = `{
	"defaultAction": "deny",
	"searchDomains": [".corp.internal", ".lab.internal"],
	"rules": [
		{"type": "hostname", "value": "job.example.com", "action": "allow"},
		{"type": "hostname", "value": "denied.example.com", "action": "deny"},
		{"type": "hostname", "value": "*.lab.internal", "ports": [{"port": 80, "protocol": "tcp"}], "action": "deny"},
		{"type": "hostname", "value": "bastion", "ports": [{"port": 22, "protocol": "tcp"}], "action": "allow"}
	],
	"steps": [
		{"id": "fetch", "rules": [
			{"type": "hostname", "value": "step.example.com", "ports": [{"port": 443, "protocol": "tcp"}]},
			{"type": "hostname", "value": "x.denied.example.com"},
			{"type": "hostname", "value": "bastion.lab.internal"},
			{"type": "hostname", "value": "*.cdn-step.example.net"},
			{"type": "hostname", "value": "svc.corp.internal"}
		]},
		{"id": "deploy", "rules": [
			{"type": "hostname", "value": "deploy.example.com", "ports": [{"port": 80, "protocol": "tcp"}]}
		]}
	]
}`

const (
	policyFetch  uint32 = 1
	policyDeploy uint32 = 2
)

var (
	tcp443 = []config.Port{{Port: 443, Protocol: config.ProtocolTCP}}
	tcp80  = []config.Port{{Port: 80, Protocol: config.ProtocolTCP}}
)

// TestStepWriters is the table of every DNS-path entry point that installs
// a rule's IPs. Each row drives one, with the shared policy, and checks
// where the IPs landed: a step-only name's IPs under the steps whose rules
// allow it, and never under the job's policy. Writers outside this package
// are pinned where they live: UpdateAllowlistTC (firewall,
// TestUpdateAllowlistTC_StepRules), AddPolicyIP's refusal of the job's
// policy (firewall, TestAddPolicyIP_RefusesTheJobsPolicy), and the
// late-allow (events, TestTryLateAllow_StepOnlyNameWritesNothing), whose
// writer interface has no step write at all.
func TestStepWriters(t *testing.T) {
	tests := []struct {
		name     string
		noPolicy bool // drive loads the policy itself
		drive    func(t *testing.T, s *Server, fw *recordingFirewall)
		step     map[uint32]map[string][]config.Port // what each step policy must hold
		job      []string                            // the job's allows
	}{
		{
			name: "answer: a step's rule",
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.1"))
			},
			step: map[uint32]map[string][]config.Port{policyFetch: {"10.1.0.1": tcp443}},
		},
		{
			name: "answer: a step's pattern",
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				answer(s, "a.cdn-step.example.net", aResponse("a.cdn-step.example.net", "10.1.0.2"))
			},
			step: map[uint32]map[string][]config.Port{policyFetch: {"10.1.0.2": nil}},
		},
		{
			name: "answer: another step's rule",
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				answer(s, "deploy.example.com", aResponse("deploy.example.com", "10.1.0.3"))
			},
			step: map[uint32]map[string][]config.Port{policyDeploy: {"10.1.0.3": tcp80}},
		},
		{
			name: "answer: a step's chain, in one response",
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				answer(s, "step.example.com", makeCNAMEResponse("step.example.com.", []string{"edge.akamai.example"}, "10.1.0.4"))
			},
			step: map[uint32]map[string][]config.Port{policyFetch: {"10.1.0.4": tcp443}},
		},
		{
			name: "answer: a step's chain, split across queries",
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				answer(s, "step.example.com", makeCNAMEResponse("step.example.com.", []string{"edge2.akamai.example"}, ""))
				answer(s, "edge2.akamai.example", makeCNAMEResponse("edge2.akamai.example.", []string{"edge3.akamai.example"}, ""))
				answer(s, "edge3.akamai.example", aResponse("edge3.akamai.example", "10.1.0.5"))
			},
			step: map[uint32]map[string][]config.Port{policyFetch: {"10.1.0.5": tcp443}},
		},
		{
			name: "answer: a bypass-suffix name a step allows",
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				answer(s, "svc.corp.internal", aResponse("svc.corp.internal", "10.1.0.6"))
			},
			step: map[uint32]map[string][]config.Port{policyFetch: {"10.1.0.6": nil}},
		},
		{
			name: "answer: the job's name",
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				answer(s, "job.example.com", aResponse("job.example.com", "10.2.0.1"))
			},
			job: []string{"10.2.0.1"},
		},
		{
			name: "answer: the job's deny on a parent beats the step",
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				answer(s, "x.denied.example.com", aResponse("x.denied.example.com", "10.1.0.7"))
				answer(s, "x.denied.example.com", makeCNAMEResponse("x.denied.example.com.", []string{"edge4.akamai.example"}, ""))
				answer(s, "edge4.akamai.example", aResponse("edge4.akamai.example", "10.1.0.8"))
			},
		},
		{
			name: "answer: the job's deny on some ports beats the step",
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				answer(s, "bastion.lab.internal", aResponse("bastion.lab.internal", "10.2.0.2"))
			},
			job: []string{"10.2.0.2"},
		},
		{
			name:     "backfill: a name seen before the policy loaded",
			noPolicy: true,
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				answer(s, "deploy.example.com", aResponse("deploy.example.com", "10.1.0.9"))
				loadStepPolicy(t, s.config, stepWritersPolicy)
				s.ApplyRulesToTrackedHostnames()
			},
			step: map[uint32]map[string][]config.Port{policyDeploy: {"10.1.0.9": tcp80}},
		},
		{
			name: "backfill: a step's rule and chain, seen before the firewall",
			drive: func(t *testing.T, s *Server, fw *recordingFirewall) {
				s.firewall = nil
				answer(s, "step.example.com", makeCNAMEResponse("step.example.com.", []string{"edge5.akamai.example"}, "10.1.0.10"))
				answer(s, "edge5.akamai.example", aResponse("edge5.akamai.example", "10.1.0.11"))
				s.SetFirewall(fw)
				s.ApplyRulesToTrackedHostnames()
			},
			step: map[uint32]map[string][]config.Port{policyFetch: {"10.1.0.10": tcp443, "10.1.0.11": tcp443}},
		},
		{
			name: "answer: the chain of a step the policy dropped",
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				answer(s, "step.example.com", makeCNAMEResponse("step.example.com.", []string{"edge6.akamai.example"}, ""))
				loadStepPolicy(t, s.config, `{"defaultAction": "deny", "rules": [],
					"steps": [{"id": "deploy", "rules": [{"type": "hostname", "value": "deploy.example.com"}]}]}`)
				answer(s, "edge6.akamai.example", aResponse("edge6.akamai.example", "10.1.0.13"))
			},
		},
		{
			name: "answer: the chain of a step the policy renumbered",
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				answer(s, "step.example.com", makeCNAMEResponse("step.example.com.", []string{"edge7.akamai.example"}, ""))
				loadStepPolicy(t, s.config, `{"defaultAction": "deny", "rules": [], "steps": [
					{"id": "deploy", "rules": [{"type": "hostname", "value": "deploy.example.com"}]},
					{"id": "fetch", "rules": [{"type": "hostname", "value": "step.example.com"}]}]}`)
				answer(s, "edge7.akamai.example", aResponse("edge7.akamai.example", "10.1.0.14"))
			},
			step: map[uint32]map[string][]config.Port{2: {"10.1.0.14": tcp443}},
		},
		{
			name: "startup pre-population: the system cache's answer",
			drive: func(t *testing.T, s *Server, _ *recordingFirewall) {
				require.Contains(t, s.config.GetTrackedHostnames(), "step.example.com")
				s.RecordSystemCacheAnswer("step.example.com", []string{"10.1.0.12"})
				s.ApplyRulesToTrackedHostnames()
			},
			step: map[uint32]map[string][]config.Port{policyFetch: {"10.1.0.12": tcp443}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.NewConfigManager()
			fw := newRecordingFirewall()
			s := newStepTestServer(t, cfg, fw)
			if !tt.noPolicy {
				loadStepPolicy(t, cfg, stepWritersPolicy)
			}
			tt.drive(t, s, fw)

			fw.mu.Lock()
			defer fw.mu.Unlock()
			assert.Zero(t, fw.policy0, "a step write named the job's policy")
			for ip := range fw.jobAllow {
				assert.Contains(t, tt.job, ip, "the job's policy got %s", ip)
			}
			for _, ip := range tt.job {
				assert.Contains(t, fw.jobAllow, ip)
			}
			for policy, ips := range fw.step {
				assert.Equal(t, tt.step[policy], ips, "step policy %d", policy)
			}
			for policy, ips := range tt.step {
				assert.Equal(t, ips, fw.step[policy], "step policy %d", policy)
			}
			// A step's chain teaches the job nothing.
			for _, target := range []string{"edge.akamai.example", "edge2.akamai.example", "edge3.akamai.example", "edge5.akamai.example"} {
				_, ok := s.cnameAllowed.Get(target)
				assert.False(t, ok, "the job learned %s from a step's chain", target)
			}
		})
	}
}

// The pre-resolve of a CNAME-only answer's target fires for a name a step
// allows, and installs the target's IPs under the step.
func TestStepWriters_PreResolve(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	upstream := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if r.Question[0].Name == "edge.step.example.net." && r.Question[0].Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("10.1.0.20"),
				})
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = upstream.ActivateAndServe() }()
	defer func() { _ = upstream.Shutdown() }()

	cfg := config.NewConfigManager()
	loadStepPolicy(t, cfg, stepWritersPolicy)
	fw := newRecordingFirewall()
	fw.stepAdd = make(chan struct{}, 4)
	s := newStepTestServer(t, cfg, fw)
	s.upstream = pc.LocalAddr().String()
	s.preResolved = newLRUCache[string, struct{}](100)

	answer(s, "step.example.com", makeCNAMEResponse("step.example.com.", []string{"edge.step.example.net"}, ""))
	select {
	case <-fw.stepAdd:
	case <-time.After(5 * time.Second):
		t.Fatal("no pre-resolve install for the step's chain target")
	}
	assert.Equal(t, map[string][]config.Port{"10.1.0.20": tcp443}, fw.stepIPs(policyFetch))
	assert.False(t, fw.jobAllows("10.1.0.20"))
}

// Two steps' chains to one target each keep their own ports, and a step's
// own rule for a name outranks its chain to it.
func TestStepWriters_PerStepChains(t *testing.T) {
	cfg := config.NewConfigManager()
	loadStepPolicy(t, cfg, `{
		"defaultAction": "deny",
		"rules": [],
		"steps": [
			{"id": "a", "rules": [
				{"type": "hostname", "value": "a.example.com", "ports": [{"port": 443, "protocol": "tcp"}]},
				{"type": "hostname", "value": "shared.edge.example", "ports": [{"port": 8443, "protocol": "tcp"}]}
			]},
			{"id": "b", "rules": [{"type": "hostname", "value": "b.example.com", "ports": [{"port": 80, "protocol": "tcp"}]}]}
		]
	}`)
	fw := newRecordingFirewall()
	s := newStepTestServer(t, cfg, fw)
	answer(s, "a.example.com", makeCNAMEResponse("a.example.com.", []string{"shared.edge.example"}, ""))
	answer(s, "b.example.com", makeCNAMEResponse("b.example.com.", []string{"shared.edge.example"}, ""))
	answer(s, "shared.edge.example", aResponse("shared.edge.example", "10.1.0.30"))

	assert.Equal(t, map[string][]config.Port{"10.1.0.30": {{Port: 8443, Protocol: config.ProtocolTCP}}}, fw.stepIPs(1),
		"step a's own rule for the target decides, not its chain")
	assert.Equal(t, map[string][]config.Port{"10.1.0.30": tcp80}, fw.stepIPs(2))
	assert.False(t, fw.jobAllows("10.1.0.30"))
}

// A refused step install (the step budget full) leaves nothing installed and
// the answer still served; a failed one likewise.
func TestStepWriters_RefusalFailsClosed(t *testing.T) {
	for _, stepErr := range []error{firewall.ErrStepBudget, errors.New("map write failed")} {
		cfg := config.NewConfigManager()
		loadStepPolicy(t, cfg, stepWritersPolicy)
		fw := newRecordingFirewall()
		fw.stepErr = stepErr
		s := newStepTestServer(t, cfg, fw)
		answer(s, "step.example.com", aResponse("step.example.com", "10.1.0.40"))
		answer(s, "job.example.com", aResponse("job.example.com", "10.2.0.40"))
		assert.Empty(t, fw.stepIPs(policyFetch))
		assert.False(t, fw.jobAllows("10.1.0.40"))
		assert.True(t, fw.jobAllows("10.2.0.40"))
	}
}

// The query filter takes the union of the job's and the steps' allows, with
// the job's deny first.
func TestStepQueryFilter(t *testing.T) {
	cfg := config.NewConfigManager()
	loadStepPolicy(t, cfg, stepWritersPolicy)
	s := newStepTestServer(t, cfg, newRecordingFirewall())
	s.filterQueries = true

	for name, want := range map[string]bool{
		"job.example.com":        true,
		"step.example.com":       true,
		"API.Step.example.com":   true,
		"a.cdn-step.example.net": true,
		"deploy.example.com":     true,
		"x.denied.example.com":   false, // the job's deny wins over the step's allow
		"denied.example.com":     false,
		"bastion.lab.internal":   true,
		"edge9.akamai.example":   false,
		"elsewhere.example.org":  false,
	} {
		assert.Equal(t, want, s.isQueryAllowed(name, dns.TypeA), name)
	}

	// A step's chain opens its targets to queries.
	answer(s, "step.example.com", makeCNAMEResponse("step.example.com.", []string{"edge9.akamai.example"}, ""))
	assert.True(t, s.isQueryAllowed("edge9.akamai.example", dns.TypeA))
	assert.True(t, s.isQueryAllowed("EDGE9.akamai.example", dns.TypeA))

	// A load whose steps drop "fetch" takes its chains' queries with it.
	loadStepPolicy(t, cfg, `{"defaultAction": "deny", "rules": [], "steps": [{"id": "deploy", "rules": [{"type": "hostname", "value": "deploy.example.com"}]}]}`)
	assert.False(t, s.isQueryAllowed("edge9.akamai.example", dns.TypeA))
	assert.False(t, s.isQueryAllowed("step.example.com", dns.TypeA))
	assert.True(t, s.isQueryAllowed("deploy.example.com", dns.TypeA))
}

// A step's chain learns its targets for the running max of the hops' TTLs,
// seeded across queries by the parent entry's remaining life, and capped,
// as the job's chain learning does.
func TestStepChainTTL(t *testing.T) {
	cfg := config.NewConfigManager()
	loadStepPolicy(t, cfg, stepWritersPolicy)
	s := newStepTestServer(t, cfg, newRecordingFirewall())
	cname := func(owner, target string, ttl uint32) *dns.Msg {
		return &dns.Msg{
			MsgHdr: dns.MsgHdr{Response: true, Rcode: dns.RcodeSuccess},
			Answer: []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: dns.Fqdn(target),
			}},
		}
	}
	expiresIn := func(name string) time.Duration {
		_, exp, ok := s.steps.cname.GetWithExpiry(name)
		require.True(t, ok, name)
		return time.Until(exp)
	}

	answer(s, "step.example.com", cname("step.example.com", "hop1.example", 3000))
	answer(s, "hop1.example", cname("hop1.example", "hop2.example", 30))
	assert.Greater(t, expiresIn("hop2.example"), 2900*time.Second, "the ancestor's reach carries across queries")

	answer(s, "step.example.com", cname("step.example.com", "hop3.example", 10_000_000))
	assert.LessOrEqual(t, expiresIn("hop3.example"), maxDerivedCNAMETTL*time.Second)
}

func TestChainReach(t *testing.T) {
	assert.Equal(t, uint32(maxDerivedCNAMETTL), chainReach(time.Time{}))
	assert.Equal(t, uint32(maxDerivedCNAMETTL), chainReach(time.Now().Add(48*time.Hour)))
	got := chainReach(time.Now().Add(100 * time.Second))
	assert.True(t, got >= 98 && got <= 100, "%d", got)
	assert.Zero(t, chainReach(time.Now().Add(-time.Second)))
}

func TestMergeStepDerived(t *testing.T) {
	got := mergeStepDerived(
		stepDerived{"a": {ports: tcp443, chain: []string{"a.example", "t"}}},
		stepDerived{"a": {ports: tcp80, chain: []string{"a2.example", "t"}}, "b": {ports: tcp80, chain: []string{"b.example", "t"}}},
	)
	assert.ElementsMatch(t, append(slices.Clone(tcp443), tcp80...), got["a"].ports)
	assert.Equal(t, []string{"a2.example", "t"}, got["a"].chain)
	assert.Equal(t, tcp80, got["b"].ports, "a step new to the target keeps its own ports")
}

// TestStepWriters_Property: for random policies whose step rules name only
// step-only names, and random answers to them (plain, chained in one
// response, chained across queries), in random order with backfills in
// between, nothing lands in the job's policy; and each step-only name's IPs
// land under exactly the steps whose rules (or chains) allow it, unless the
// job denies the name.
func TestStepWriters_Property(t *testing.T) {
	for seed := range uint64(40) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, 105))
			const steps = 3

			// Rules. The job allows names under job.test and denies names
			// under deny.test; each step allows some of its own names, a
			// zone, a pattern, and some names under deny.test.
			type stepRule struct{ value, port string }
			var stepRules [steps][]stepRule
			for k := range steps {
				for i := range 4 {
					if rng.IntN(2) == 0 {
						stepRules[k] = append(stepRules[k], stepRule{value: fmt.Sprintf("n%d.s%d.step.test", i, k)})
					}
				}
				if rng.IntN(2) == 0 {
					stepRules[k] = append(stepRules[k], stepRule{value: fmt.Sprintf("z%d.step.test", k), port: `, "ports": [{"port": 443, "protocol": "tcp"}]`})
				}
				if rng.IntN(2) == 0 {
					stepRules[k] = append(stepRules[k], stepRule{value: fmt.Sprintf("*.p%d.step.test", k)})
				}
				if rng.IntN(2) == 0 {
					stepRules[k] = append(stepRules[k], stepRule{value: fmt.Sprintf("d%d.deny.test", k)})
				}
				// Every step keeps one rule, so policy ids stay k+1.
				stepRules[k] = append(stepRules[k], stepRule{value: fmt.Sprintf("always%d.step.test", k)})
			}
			var sb strings.Builder
			sb.WriteString(`{"defaultAction": "deny", "rules": [
				{"type": "hostname", "value": "job.test", "action": "allow"},
				{"type": "hostname", "value": "deny.test", "action": "deny"}], "steps": [`)
			for k := range steps {
				if k > 0 {
					sb.WriteString(",")
				}
				fmt.Fprintf(&sb, `{"id": "s%d", "rules": [`, k)
				for i, r := range stepRules[k] {
					if i > 0 {
						sb.WriteString(",")
					}
					fmt.Fprintf(&sb, `{"type": "hostname", "value": %q%s}`, r.value, r.port)
				}
				sb.WriteString("]}")
			}
			sb.WriteString("]}")

			// Queried names: every step-only name a rule could name, and some
			// job names.
			var names []string
			for k := range steps {
				for i := range 4 {
					names = append(names, fmt.Sprintf("n%d.s%d.step.test", i, k))
				}
				names = append(names, fmt.Sprintf("a.z%d.step.test", k), fmt.Sprintf("x.p%d.step.test", k),
					fmt.Sprintf("d%d.deny.test", k), fmt.Sprintf("always%d.step.test", k))
			}
			names = append(names, "www.job.test", "api.job.test")

			cfg := config.NewConfigManager()
			fw := newRecordingFirewall()
			s := newStepTestServer(t, cfg, fw)
			s.filterQueries = rng.IntN(2) == 0
			loaded := false
			if rng.IntN(3) > 0 {
				loadStepPolicy(t, cfg, sb.String())
				loaded = true
			}

			// owner maps each answered IP to the name whose step rules
			// decide it: the queried name, or the chain's origin.
			owner := map[string]string{}
			nextIP := 0
			ip := func(job bool) string {
				nextIP++
				if job {
					return fmt.Sprintf("10.2.%d.%d", nextIP/250, nextIP%250+1)
				}
				return fmt.Sprintf("10.1.%d.%d", nextIP/250, nextIP%250+1)
			}
			for range 60 {
				name := names[rng.IntN(len(names))]
				job := strings.HasSuffix(name, ".job.test")
				// An answer reaches enforcement unless the filter refuses
				// its query; a refused one is installed nowhere, ever.
				decider := ""
				if s.isQueryAllowed(name, dns.TypeA) {
					decider = name
				}
				switch rng.IntN(4) {
				case 0, 1:
					a := ip(job)
					owner[a] = decider
					answer(s, name, aResponse(name, a))
				case 2:
					target := fmt.Sprintf("t%d.edge.test", nextIP)
					a := ip(job)
					owner[a] = decider
					answer(s, name, makeCNAMEResponse(dns.Fqdn(name), []string{target}, a))
				case 3:
					// Split across queries, the target's IPs are its origin's
					// only if the origin's rules were loaded to learn the chain.
					if !loaded {
						decider = ""
					}
					target := fmt.Sprintf("t%d.edge.test", nextIP)
					answer(s, name, makeCNAMEResponse(dns.Fqdn(name), []string{target}, ""))
					a := ip(job)
					owner[a] = decider
					answer(s, target, aResponse(target, a))
				}
				if rng.IntN(8) == 0 {
					if !loaded {
						loadStepPolicy(t, cfg, sb.String())
						loaded = true
					}
					s.ApplyRulesToTrackedHostnames()
				}
			}
			if !loaded {
				loadStepPolicy(t, cfg, sb.String())
			}
			s.ApplyRulesToTrackedHostnames()

			// allows reports whether step k's rules allow name, by the
			// rules' own semantics: exact, parent zone, one-label pattern.
			allows := func(k int, name string) bool {
				for _, r := range stepRules[k] {
					if v, ok := strings.CutPrefix(r.value, "*."); ok {
						if label, rest, found := strings.Cut(name, "."); found && label != "" && rest == v {
							return true
						}
						continue
					}
					if name == r.value || strings.HasSuffix(name, "."+r.value) {
						return true
					}
				}
				return false
			}

			fw.mu.Lock()
			defer fw.mu.Unlock()
			for a := range fw.jobAllow {
				require.True(t, strings.HasPrefix(a, "10.2."), "the job's policy got %s, an IP of %s", a, owner[a])
			}
			for k := range steps {
				for a := range fw.step[uint32(k+1)] {
					name := owner[a]
					require.True(t, allows(k, name), "step %d got %s, an IP of %s", k, a, name)
					require.False(t, strings.HasSuffix(name, ".deny.test"), "step %d got %s past the job's deny on %s", k, a, name)
				}
			}
			for a, name := range owner {
				if strings.HasSuffix(name, ".deny.test") || strings.HasSuffix(name, ".job.test") {
					continue
				}
				for k := range steps {
					_, got := fw.step[uint32(k+1)][a]
					require.Equal(t, allows(k, name), got, "step %d and %s (an IP of %s)", k, a, name)
				}
			}
		})
	}
}
