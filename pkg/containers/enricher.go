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

package containers

import (
	"sync/atomic"

	"github.com/code-cargo/cargowall/pkg/events"
	"github.com/code-cargo/cargowall/pkg/origin"
)

// Enricher is a late-binding events.ContainerEnricher. The event pipeline
// starts early in daemon startup, but container tracking can only start
// after the dockerd restart severs-proofs the event subscription — so the
// pipeline gets this shell up front and Bind attaches the live Tracker once
// it exists. Until then (and if tracking never comes up) Enrich is a no-op,
// which is the correct degradation: unenriched events classify to the
// stricter tiers.
type Enricher struct {
	tracker atomic.Pointer[Tracker]
}

// Bind attaches the live tracker; safe to call once tracking starts.
func (e *Enricher) Bind(t *Tracker) { e.tracker.Store(t) }

// Enrich implements events.ContainerEnricher.
func (e *Enricher) Enrich(audit *events.AuditEvent, ev *events.BpfBlockedEvent) {
	if t := e.tracker.Load(); t != nil {
		t.Enrich(audit, ev)
	}
}

// DecorateVerdict adds container identity to a cgroup-hook outcome when the
// tracker is live. A verdict that beats docker tracking startup simply goes
// undecorated — it is still reported in full by pkg/events, just without a
// container id.
func (e *Enricher) DecorateVerdict(audit *events.AuditEvent, rec origin.Record) {
	if t := e.tracker.Load(); t != nil {
		t.DecorateVerdict(audit, rec)
	}
}
