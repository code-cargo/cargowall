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
	"bufio"
	"cmp"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	cargowallNet "github.com/code-cargo/cargowall/pkg/network"
)

// systemd-resolved's synthetic names (#126).
//
// resolved answers these from its own state and never sends them upstream:
// "_gateway" is the default-route gateway(s) ordered by metric, "_outbound"
// the local address(es) used towards them, "_localdnsstub" and
// "_localdnsproxy" its two loopback listeners. The redirect DNATs the stub
// (127.0.0.53) to this proxy, and the proxy's upstream is deliberately the
// resolver BEHIND resolved (the action's detectDnsUpstream skips the stub so
// the proxy cannot loop into itself), so without this file every one of them
// NXDOMAINs for the length of a run — REFUSED under enforce, silently under
// audit, where no connection is ever attempted and nothing is logged.
// "localhost" is synthetic too but survives: nsswitch consults /etc/hosts
// first.
//
// Answered ahead of the filter gate and the cache, mirroring resolved's own
// precedence, and only while resolved is actually running (the same probe the
// cache flush uses), so the proxy never invents a name the host's resolver
// would not have answered. Host listeners only: a container's native path
// (embedded DNS → the host's real upstream) never resolved these either, and
// the host's gateway is the wrong answer inside a container netns anyway.
//
// The search-expanded form is answered too, with NXDOMAIN: every stub
// resolver tries "_gateway.<search>" before "_gateway" on a host whose
// resolv.conf carries a search list, so that is the first query on the wire
// for the name — see answerSyntheticNXDomain for why the rcode matters.
//
// Resolution only, never egress. The answer feeds neither hostnameIPs nor the
// firewall: reaching the gateway stays an explicit CIDR decision for the
// operator, since a route-derived allow would grant every job the host.

const (
	syntheticGateway  = "_gateway"
	syntheticOutbound = "_outbound"
	syntheticDNSStub  = "_localdnsstub"
	syntheticDNSProxy = "_localdnsproxy"
)

// syntheticNames is the set resolved synthesizes from local state.
var syntheticNames = []string{syntheticGateway, syntheticOutbound, syntheticDNSStub, syntheticDNSProxy}

var (
	localDNSStubIP  = net.IPv4(127, 0, 0, 53)
	localDNSProxyIP = net.IPv4(127, 0, 0, 54)
)

// Route-table sources, the interface-address lookup and the client resolver
// config, vars so tests can point them at fixtures.
var (
	resolvConfPath   = "/etc/resolv.conf"
	procNetRoute     = "/proc/net/route"
	procNetIPv6Route = "/proc/net/ipv6_route"
	interfaceAddrs   = func(name string) ([]net.Addr, error) {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			return nil, err
		}
		return ifi.Addrs()
	}
)

// Route flags shared by both /proc tables.
const (
	rtfUp      = 0x1
	rtfGateway = 0x2
)

// syntheticQuery classifies a wire-form query name (trailing dot): the bare
// synthetic name, its search-expanded form — first label synthetic, the rest
// a suffix on the host's own search list — or neither. Only the expansions
// a resolver on THIS host would generate count: "_gateway.example.com" is an
// ordinary query, since that could be a real owner name in someone's zone.
// resolv.conf is consulted only once the first label has matched, so
// ordinary queries never touch it, and reading it per hit rather than once
// at Start keeps a DHCP-rewritten search list current.
func syntheticQuery(qname string) (name string, expanded, ok bool) {
	full := strings.ToLower(strings.TrimSuffix(qname, "."))
	first, rest, hasRest := strings.Cut(full, ".")
	if !slices.Contains(syntheticNames, first) {
		return "", false, false
	}
	if !hasRest {
		return first, false, true
	}
	if slices.Contains(hostSearchDomains(resolvConfPath), rest) {
		return first, true, true
	}
	return "", false, false
}

// hostSearchDomains reads the search list clients expand single-label names
// with: the last "search" or "domain" directive wins, as glibc and Go read
// it. Lowercased, trailing dots trimmed. An unreadable file is an empty
// list — no expansion is then recognised, and the query takes the ordinary
// path rather than the proxy guessing at one.
func hostSearchDomains(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var domains []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || (fields[0] != "search" && fields[0] != "domain") {
			continue
		}
		domains = domains[:0]
		for _, d := range fields[1:] {
			if strings.HasPrefix(d, "#") || strings.HasPrefix(d, ";") {
				break
			}
			domains = append(domains, strings.ToLower(strings.TrimSuffix(d, ".")))
		}
	}
	return domains
}

// probeSynthetic decides at Start whether to answer synthetic names: only
// when systemd-resolved is running. A probe failure disables the feature
// with a Warn rather than guessing either way.
func (s *Server) probeSynthetic() bool {
	running, err := cargowallNet.SystemdResolvedRunning()
	if err != nil {
		s.logger.Warn("Could not probe systemd-resolved; not answering its synthetic names", "error", err)
		return false
	}
	if running {
		s.logger.Info("Answering systemd-resolved synthetic names locally", "names", syntheticNames)
	}
	return running
}

// answerSynthetic writes the local answer for a synthetic name. The shape
// matches resolved's: authoritative, TTL 0 (the route can change mid-run),
// A/AAAA carry the addresses of that family, every other qtype is NODATA.
// A route-table read failure is SERVFAIL — "try again", which is what a
// broken resolver should say — while "no default route" is an honest empty
// answer, exactly as resolved reports it.
func (s *Server) answerSynthetic(w dns.ResponseWriter, r *dns.Msg, name string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	ips, err := syntheticAddrs(name)
	if err != nil {
		s.logger.Warn("Failed to derive synthetic DNS answer", "name", name, "error", err)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	for _, ip := range ips {
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 0}
		switch {
		case q.Qtype == dns.TypeA && ip.To4() != nil:
			hdr.Rrtype = dns.TypeA
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip.To4()})
		case q.Qtype == dns.TypeAAAA && ip.To4() == nil:
			hdr.Rrtype = dns.TypeAAAA
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip.To16()})
		}
	}
	s.logger.Debug("DNS synthetic answer",
		"name", name,
		"type", dns.TypeToString[q.Qtype],
		"answers", len(m.Answer))
	w.WriteMsg(m)
}

// answerSyntheticNXDomain answers the search-expanded form of a synthetic
// name — "_gateway.lan" on a host whose resolv.conf carries "search lan".
// Every stub resolver tries the expanded forms of a single-label name
// before the name itself, so this is the first query on the wire for
// "_gateway", not a name the client wanted. Natively it reaches the upstream
// and NXDOMAINs — resolved does not synthesize it — and the proxy says the
// same thing itself: no upstream round trip, no block record for a name the
// client is about to abandon, and NXDOMAIN rather than REFUSED because
// NXDOMAIN is the one rcode every resolver treats as "try the next form".
// c-ares ends its search on a REFUSED multi-label attempt (its issue #852
// carve-out is single-label only), so the REFUSED the filter gate returned
// here left "_gateway" unresolvable for c-ares clients under enforce while
// glibc and Go fell through to the bare name.
func (s *Server) answerSyntheticNXDomain(w dns.ResponseWriter, r *dns.Msg, name string) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeNameError)
	m.Authoritative = true
	s.logger.Debug("DNS synthetic search-expanded form answered NXDOMAIN",
		"query", r.Question[0].Name,
		"name", name)
	w.WriteMsg(m)
}

// syntheticAddrs returns the addresses a synthetic name resolves to.
func syntheticAddrs(name string) ([]net.IP, error) {
	switch name {
	case syntheticDNSStub:
		return []net.IP{localDNSStubIP}, nil
	case syntheticDNSProxy:
		return []net.IP{localDNSProxyIP}, nil
	}
	routes, err := defaultRoutes()
	if err != nil {
		return nil, err
	}
	if name == syntheticGateway {
		ips := make([]net.IP, 0, len(routes))
		for _, rt := range routes {
			ips = append(ips, rt.gateway)
		}
		return ips, nil
	}
	return outboundAddrs(routes), nil
}

// defaultRoute is one gateway default route from the kernel tables.
type defaultRoute struct {
	iface   string
	gateway net.IP
	metric  uint32
}

// defaultRoutes reads both route tables and returns the gateway default
// routes ordered by metric, IPv4 before IPv6 at equal metric — resolved's
// "_gateway" order. The IPv6 table is optional: it is absent when the stack
// is disabled.
func defaultRoutes() ([]defaultRoute, error) {
	f, err := os.Open(procNetRoute)
	if err != nil {
		return nil, err
	}
	routes, err := parseIPv4Routes(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", procNetRoute, err)
	}

	if f, err := os.Open(procNetIPv6Route); err == nil {
		v6, err := parseIPv6Routes(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", procNetIPv6Route, err)
		}
		routes = append(routes, v6...)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	slices.SortStableFunc(routes, func(a, b defaultRoute) int { return cmp.Compare(a.metric, b.metric) })
	return routes, nil
}

// parseIPv4Routes reads /proc/net/route: one header line, then "Iface
// Destination Gateway Flags RefCnt Use Metric Mask ..." with addresses as
// little-endian hex and the counters decimal. A default route has a zero
// destination and mask; only up gateway routes count.
func parseIPv4Routes(r io.Reader) ([]defaultRoute, error) {
	var routes []defaultRoute
	sc := bufio.NewScanner(r)
	header := true
	for sc.Scan() {
		if header {
			header = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("flags %q: %w", f[3], err)
		}
		if flags&rtfUp == 0 || flags&rtfGateway == 0 {
			continue
		}
		gw, err := hex.DecodeString(f[2])
		if err != nil || len(gw) != net.IPv4len {
			return nil, fmt.Errorf("gateway %q: not a little-endian IPv4 address", f[2])
		}
		metric, err := strconv.ParseUint(f[6], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("metric %q: %w", f[6], err)
		}
		routes = append(routes, defaultRoute{
			iface:   f[0],
			gateway: net.IPv4(gw[3], gw[2], gw[1], gw[0]),
			metric:  uint32(metric),
		})
	}
	return routes, sc.Err()
}

// parseIPv6Routes reads /proc/net/ipv6_route: no header, "dst dstlen src
// srclen nexthop metric refcnt use flags iface", every field hex. A default
// route has a zero destination of prefix length 0; the kernel's unreachable
// default on lo carries no gateway flag and is skipped with the rest.
func parseIPv6Routes(r io.Reader) ([]defaultRoute, error) {
	var routes []defaultRoute
	sc := bufio.NewScanner(r)
	zero := strings.Repeat("0", 32)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[0] != zero || f[1] != "00" {
			continue
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("flags %q: %w", f[8], err)
		}
		if flags&rtfUp == 0 || flags&rtfGateway == 0 {
			continue
		}
		gw, err := hex.DecodeString(f[4])
		if err != nil || len(gw) != net.IPv6len {
			return nil, fmt.Errorf("gateway %q: not an IPv6 address", f[4])
		}
		metric, err := strconv.ParseUint(f[5], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("metric %q: %w", f[5], err)
		}
		routes = append(routes, defaultRoute{iface: f[9], gateway: net.IP(gw), metric: uint32(metric)})
	}
	return routes, sc.Err()
}

// outboundAddrs derives "_outbound": for each default route, the address on
// its interface that shares the gateway's subnet — the source the kernel
// picks for traffic towards it — falling back to the interface's first
// global unicast address of that family. Order follows the routes;
// duplicates (two routes out of one interface) collapse. An interface that
// cannot be read contributes nothing rather than failing the answer.
func outboundAddrs(routes []defaultRoute) []net.IP {
	var out []net.IP
	seen := make(map[string]bool)
	for _, rt := range routes {
		addrs, err := interfaceAddrs(rt.iface)
		if err != nil {
			continue
		}
		v4 := rt.gateway.To4() != nil
		var pick, fallback net.IP
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || (ipn.IP.To4() != nil) != v4 {
				continue
			}
			if ipn.Contains(rt.gateway) {
				pick = ipn.IP
				break
			}
			if fallback == nil && ipn.IP.IsGlobalUnicast() {
				fallback = ipn.IP
			}
		}
		if pick == nil {
			pick = fallback
		}
		if pick != nil && !seen[pick.String()] {
			seen[pick.String()] = true
			out = append(out, pick)
		}
	}
	return out
}
