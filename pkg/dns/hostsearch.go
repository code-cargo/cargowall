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
	"os"
	"strings"
)

// resolvConfPath is the client resolver config whose search list is
// honoured; a var so tests can point it at a fixture.
var resolvConfPath = "/etc/resolv.conf"

// seedHostSearchDomains publishes the host's resolv.conf search list to the
// config manager as a strip-only suffix source (#127). Read once at Start:
// the list is boot-time DHCP state and a job is short-lived.
func (s *Server) seedHostSearchDomains() {
	domains := hostSearchDomains(resolvConfPath)
	s.config.SetHostSearchDomains(domains, s.logger)
	if len(domains) > 0 {
		s.logger.Info("Host search domains active for rule matching", "domains", domains)
	}
}

// hostSearchDomains reads resolv.conf's search list: the last "search" or
// "domain" directive wins, as glibc reads it; unreadable yields nil.
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
