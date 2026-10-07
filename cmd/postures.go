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

// Requested-vs-applied postures for the layers a flag requests but the
// runtime can fail to deliver: the cgroup egress hook and the L7 layer riding
// it. A lost enforce rung fails startup — the operator asked for a guarantee
// the job would not have. A lost observe rung only warns, and is recorded so
// the job summary can say the measurement never ran: an observe run that
// reports no would-blocks reads exactly like a clean one.
package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	cargowallEbpf "github.com/code-cargo/cargowall/pkg/ebpf"
)

// posturesFile carries the posture record from `cargowall start` to
// `cargowall summary` (separate process invocations), the same hand-off the
// downgrade record uses. A var so tests can redirect it.
var posturesFile = "/tmp/cargowall-postures"

// Posture names, spelled as their flags so errors and the summary read as
// the operator's own configuration.
const (
	postureContainerEgress = "container-egress"
	postureTLSSNI          = "tls-sni"
)

// maxPostureReasonBytes bounds a reason: it lands in a job-summary table
// cell and must leave the whole record well inside readStateFile's cap.
const maxPostureReasonBytes = 300

// postureRecord is one layer's line in posturesFile. Values are flag rungs
// ("off", "observe", "enforce", "enforce-pinned").
type postureRecord struct {
	Posture   string `json:"posture"`
	Requested string `json:"requested"`
	Applied   string `json:"applied"`
	// Why Applied is not Requested; empty when they match.
	Reason string `json:"reason,omitempty"`

	off        string // this flag's own off rung, what a loss leaves applied
	failClosed bool   // the requested rung promises drops: losing it fails startup
}

func (r postureRecord) degraded() bool { return r.Applied != r.Requested }

// postureLedger knows what each layer was asked for and decides what losing
// it means. Only layers requested above off are tracked: an off layer
// promised nothing. Not nil-safe on purpose — the ledger is what turns a lost
// enforce rung into a failed start, and a missing one must not quietly
// degrade instead.
type postureLedger struct {
	records []postureRecord
	kernel  string // uname release, for verifier reasons: the budget is per-kernel
	logger  *slog.Logger
}

// newPostures registers each layer against its OWN flag's constants: the
// two flags happen to share the spellings "off" and "enforce", and neither
// the skip nor the fail-closed decision may lean on that.
func newPostures(cmd *StartCmd, kernel string, logger *slog.Logger) *postureLedger {
	p := &postureLedger{kernel: kernel, logger: logger}
	p.register(postureContainerEgress, cmd.ContainerEgress, ContainerEgressOff,
		cmd.ContainerEgress == ContainerEgressEnforce)
	p.register(postureTLSSNI, cmd.TLSSNI, TLSSNIOff,
		cmd.TLSSNI == TLSSNIEnforce || cmd.TLSSNI == TLSSNIEnforcePinned)
	return p
}

func (p *postureLedger) register(posture, requested, off string, failClosed bool) {
	if requested == "" || requested == off {
		return
	}
	p.records = append(p.records, postureRecord{
		Posture: posture, Requested: requested, Applied: requested,
		off: off, failClosed: failClosed,
	})
}

func (p *postureLedger) find(posture string) *postureRecord {
	for i := range p.records {
		if p.records[i].Posture == posture {
			return &p.records[i]
		}
	}
	return nil
}

// lose reports that posture could not come up. There is no partial descent:
// every way a layer fails leaves it computing no verdict, so the record goes
// to off — the fatal case included, so the record always agrees with the
// failure sentinel — keeping the first reason. The ledger owns the log line.
//
// A fail-closed rung returns an error the caller must fail startup with: TC
// egress would still police post-NAT traffic, but the job would run without
// the pre-NAT/loopback/bridge or name-level enforcement it asked for, and
// saying so after the fact is the fail-open direction. Any other loss warns,
// and the summary lists it.
func (p *postureLedger) lose(posture, reason string) error {
	r := p.find(posture)
	if r == nil {
		return nil // never requested: nothing was promised
	}
	if !r.degraded() {
		r.Applied = r.off
		r.Reason = truncateReason(reason)
	}
	msg := fmt.Sprintf("--%s=%s requested but could not be applied", posture, r.Requested)
	if r.failClosed {
		p.logger.Error(msg, "reason", reason)
		return fmt.Errorf("%s: %s", msg, reason)
	}
	p.logger.Warn(msg, "reason", reason)
	return nil
}

// errReason condenses a failure into a posture reason. A verifier rejection
// becomes its one-line form plus the kernel, since the same program verifies
// on one kernel and is refused on another; anything else keeps its first
// line, as wrapped errors can carry a multi-line dump.
func (p *postureLedger) errReason(err error) string {
	if err == nil {
		return ""
	}
	if rej, ok := cargowallEbpf.ParseRejection(err); ok {
		return rej.On(p.kernel)
	}
	first, _, _ := strings.Cut(err.Error(), "\n")
	return first
}

// write publishes the record for the summary step. Best-effort like the
// mode file: a failed write only costs the summary its Postures block.
func (p *postureLedger) write() {
	data, err := json.Marshal(p.records)
	if err == nil {
		err = writeSentinel(posturesFile, data)
	}
	if err != nil {
		p.logger.Warn("Failed to write postures file", "path", posturesFile, "error", err)
	}
}

// truncateReason bounds and sanitizes a reason at the writer. The reader
// sanitizes again: the file sits in world-writable /tmp.
func truncateReason(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxPostureReasonBytes {
		s = strings.ToValidUTF8(s[:maxPostureReasonBytes], "") + "..."
	}
	return sanitizeReason(s)
}

// readPostures returns the record written by `cargowall start`, or nil when
// absent (nothing requested, or an agent predating posture reporting) or
// unreadable. Read through readStateFile: the path is fixed and
// world-writable. Every string is sanitized here because it is echoed into
// markdown.
func readPostures() []postureRecord {
	sf, ok := readStateFile(posturesFile)
	if !ok {
		return nil
	}
	var recs []postureRecord
	if err := json.Unmarshal(sf.data, &recs); err != nil {
		slog.Debug("Postures record unreadable — omitting", "path", posturesFile, "error", err)
		return nil
	}
	for i := range recs {
		recs[i].Posture = sanitizeReason(recs[i].Posture)
		recs[i].Requested = sanitizeReason(recs[i].Requested)
		recs[i].Applied = sanitizeReason(recs[i].Applied)
		recs[i].Reason = truncateReason(recs[i].Reason)
	}
	return recs
}
