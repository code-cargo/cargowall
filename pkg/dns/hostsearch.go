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
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/code-cargo/cargowall/pkg/config"
)

// resolvConfPath is the client resolver config whose search list is
// honoured; a var so tests can point it at a fixture.
var resolvConfPath = "/etc/resolv.conf"

// hostSearchSource keeps the config manager's host search list (#127) in
// step with resolv.conf: a stat per query, a re-read and
// SetHostSearchDomains only when the file changes. DHCP rewrites it mid-run.
type hostSearchSource struct {
	mu      sync.Mutex
	loaded  bool
	modTime time.Time
	size    int64
	domains []string
}

// refresh returns the current search list, re-reading resolv.conf and
// pushing it to the manager when the file has changed. An absent file
// yields an empty list, and clears the manager's copy if one was pushed.
func (h *hostSearchSource) refresh(cm *config.Manager, logger *slog.Logger) []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	st, err := os.Stat(resolvConfPath)
	if err != nil {
		if h.loaded && h.domains != nil {
			cm.SetHostSearchDomains(nil, logger)
		}
		h.loaded, h.domains = true, nil
		return nil
	}
	if h.loaded && st.ModTime().Equal(h.modTime) && st.Size() == h.size {
		return h.domains
	}
	h.loaded, h.modTime, h.size = true, st.ModTime(), st.Size()
	h.domains = hostSearchDomains(resolvConfPath)
	cm.SetHostSearchDomains(h.domains, logger)
	logger.Debug("Host search domains loaded", "domains", h.domains, "path", resolvConfPath)
	return h.domains
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
