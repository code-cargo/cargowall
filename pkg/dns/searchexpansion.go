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
	"strings"

	"github.com/miekg/dns"
)

// A Kubernetes pod's resolv.conf, which containers started inside the pod
// (docker-in-docker) inherit, lists search suffixes ending in the cluster
// domain with ndots:5. So a lookup of example.com first asks for
// example.com.<namespace>.svc.cluster.local, then the other suffixes, and
// only then the bare name.

// clusterDomainSuffix ends every search suffix a pod's resolver appends.
const clusterDomainSuffix = ".cluster.local"

// namespaceSearchSuffix follows the namespace label in a pod's first search
// suffix.
const namespaceSearchSuffix = ".svc.cluster.local"

// deniedRcode is the answer to a query the policy denies, given in enforce
// mode. Names in the cluster domain get NXDOMAIN rather than REFUSED: musl
// and c-ares give up the whole search on REFUSED, so the bare name, which the
// policy may allow, would never be asked. NXDOMAIN moves the resolver on to
// the next suffix. The query is answered here either way, never forwarded.
func deniedRcode(domain string) int {
	if strings.HasSuffix(domain, clusterDomainSuffix) {
		return dns.RcodeNameError
	}
	return dns.RcodeRefused
}

// isAllowedSearchExpansion reports whether domain (lowercase, no trailing
// dot) is a name the policy allows with a pod's namespace search suffix
// appended: <allowed>.<namespace>.svc.cluster.local. Such a query is the
// resolver walking its search list, not a lookup the job asked for, so it is
// not reported as a block. Rule matching already strips the suffixes that
// carry no namespace and the default namespace's; this covers the rest.
func (s *Server) isAllowedSearchExpansion(domain string) bool {
	rest, ok := strings.CutSuffix(domain, namespaceSearchSuffix)
	if !ok {
		return false
	}
	dot := strings.LastIndexByte(rest, '.')
	if dot <= 0 {
		return false // no name in front of the namespace label
	}
	return s.config.MatchHostnameRule(rest[:dot]).HasAllow()
}
