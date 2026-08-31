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

package config

import "golang.org/x/sys/unix"

// PortsCover reports whether a rule-side port list covers (port, proto). An
// empty list means the side applies to all ports, matching rule semantics;
// otherwise the port number must match and the protocols must overlap.
//
// The single implementation of "does this rule side cover the connection?":
// the auto-allow attribution, the late-allow reconciler and the L7 name policy
// all decide a mixed verdict with it, and their answers are only consistent
// while they share this one.
func PortsCover(ports []Port, port uint16, proto ProtocolType) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p.Port == port && ProtocolsOverlap(p.Protocol, proto) {
			return true
		}
	}
	return false
}

// DstPortAllowedByRule reports whether a (dstPort, proto) tuple would be
// permitted by a rule side whose port restrictions are `ports`, taking the L4
// protocol as the raw wire byte an eBPF event or an L7 punt carries. An empty
// `ports` means all ports; an unknown L4 proto fails closed (no overlap, even
// with ProtocolAll rules) — see ProtocolFromIPProto.
func DstPortAllowedByRule(dstPort uint16, proto uint8, ports []Port) bool {
	if len(ports) == 0 {
		return true
	}
	eventProto, ok := ProtocolFromIPProto(proto)
	if !ok {
		return false
	}
	return PortsCover(ports, dstPort, eventProto)
}

// ProtocolFromIPProto maps an L4 protocol byte to the corresponding
// ProtocolType. The bool reports whether the proto is one we recognize;
// unknown protocols fail closed in DstPortAllowedByRule rather than mapping to
// ProtocolAll, so a future guard-loosening upstream can't silently widen the
// match.
func ProtocolFromIPProto(proto uint8) (ProtocolType, bool) {
	switch proto {
	case unix.IPPROTO_TCP:
		return ProtocolTCP, true
	case unix.IPPROTO_UDP:
		return ProtocolUDP, true
	case unix.IPPROTO_ICMP:
		return ProtocolICMP, true
	default:
		return "", false
	}
}
