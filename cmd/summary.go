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

// Job summary pipeline: audit log I/O, late-allow reconciliation, the legacy
// temporal step correlation, dedup, and the SaaS push. Causal step
// attribution lives in summary_attribution.go; markdown rendering lives in
// summary_render.go.
package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	cargowallv1 "github.com/code-cargo/cargowall/pb/cargowall/v1"
	"github.com/code-cargo/cargowall/pb/cargowall/v1/data"
	"github.com/code-cargo/cargowall/pkg/events"
)

// SummaryCmd generates a markdown summary correlating audit events with GitHub Actions steps
type SummaryCmd struct {
	Version string `kong:"-"` // Version passed from main

	AuditLog string `help:"Path to audit log JSON file" required:""`
	Steps    string `help:"JSON array of step timing from GitHub API" required:""`

	// API push flags (optional — skip API push if api-url is not set)
	ApiUrl        string `help:"CodeCargo API URL for pushing results" name:"api-url"`
	Token         string `help:"OIDC bearer token for API authentication"`
	JobName       string `help:"GitHub Actions job name" name:"job-name"`
	JobKey        string `help:"GitHub Actions job key (github.job)" name:"job-key"`
	Mode          string `help:"CargoWall mode (enforce/audit)"`
	DefaultAction string `help:"Default action type (allow/deny)" name:"default-action"`
	JobRunId      uint64 `help:"GitHub Actions job run ID" name:"job-run-id"`
	JobStatus     string `help:"GitHub Actions job status (success/failure/canceled/cancelled/timed_out)" name:"job-status"`

	output io.Writer // overridable for testing; defaults to os.Stdout
}

// GitHubStep represents a step from the GitHub API
type GitHubStep struct {
	Name        string    `json:"name"`
	Number      int       `json:"number"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
}

// StepEvents groups events by step
type StepEvents struct {
	Step   GitHubStep
	Events []events.AuditEvent
}

func (c *SummaryCmd) Run() error {
	if c.output == nil {
		c.output = os.Stdout
	}

	// Parse steps JSON
	var steps []GitHubStep
	if err := json.Unmarshal([]byte(c.Steps), &steps); err != nil {
		return fmt.Errorf("failed to parse steps JSON: %w", err)
	}

	// Read audit log
	auditEvents, err := c.readAuditLog()
	if err != nil {
		return fmt.Errorf("failed to read audit log: %w", err)
	}

	// Drop blocked events that a later late-allow superseded so they aren't
	// counted or pushed as denies (#83).
	auditEvents = reconcileLateAllowedBlocks(auditEvents)

	// Separate existing connection events from regular events. Step
	// boundaries are process markers, not connections — they'd render as
	// destination-less rows in the entries table, so they stay out of the
	// connection pipeline. They are not discarded: resolveOrdinalSteps maps
	// their ordinals to GitHub steps (driving both groupings), and
	// generateStepAttributionSection renders them as their own table.
	var existingConnEvents, regularEvents, stepBoundaries []events.AuditEvent
	for _, event := range auditEvents {
		switch event.EventType {
		case events.EventExistingConnection:
			existingConnEvents = append(existingConnEvents, event)
		case events.EventStepBoundary:
			stepBoundaries = append(stepBoundaries, event)
		case events.EventContainerAttribution, events.EventCgroupWouldBlock:
			// Telemetry markers, not connection outcomes. Container/exec
			// tagging describes no connection at all; a cgroup would-block
			// describes traffic that was NOT blocked (shadow mode), so
			// counting it as a block would overstate what the firewall did.
			// The audit log carries both for CI assertions and blast-radius
			// measurement; the summary renders nothing from them yet.
		default:
			regularEvents = append(regularEvents, event)
		}
	}

	// Resolve ordinals against the GitHub-REPORTED step times, BEFORE the
	// backfill below synthesizes completed_at values: a backfilled end
	// (the next step's start) makes every window abut its successor, and
	// the resolver's window tie-breaker would then capture rounding-early
	// boundaries that belong to the next step.
	ordinalSteps := resolveOrdinalSteps(stepBoundaries, steps)

	// Every push path ships per-step timestamps, so the null-completed_at
	// backfill must run before ANY of them — including the zero-network
	// early return below, whose pushToApi(nil, steps) uses steps directly
	// (GitHub always reports null for the step that is still running — the
	// post step this command executes in; next-step-start inference needs
	// no events).
	backfillStepCompletion(steps, regularEvents)

	// "No network events" check runs on the classified sets: with step
	// attribution on, the audit log always contains step_boundary rows, so
	// raw-log emptiness would never trigger and a zero-network job would
	// render a full summary of zeros instead of this concise message.
	if len(regularEvents) == 0 && len(existingConnEvents) == 0 {
		// Best-effort API push — log warning on failure but don't fail the summary
		var workflowRunLink string
		if c.ApiUrl != "" {
			var err error
			workflowRunLink, err = c.pushToApi(nil, steps, nil)
			if err != nil {
				slog.Warn("Best-effort API push failed", "error", err)
			}
		}

		fmt.Fprintln(c.output, "## CargoWall")
		fmt.Fprintln(c.output)
		if workflowRunLink != "" {
			fmt.Fprintf(c.output, "[View full details on CodeCargo](%s)\n", workflowRunLink)
		} else {
			fmt.Fprintln(c.output, "No network events were logged during this workflow run.")
		}
		return nil
	}

	// Determine if audit mode by checking blocked-type events for WouldDeny=true.
	// Allowed events never have WouldDeny set, so we must look at a blocked event.
	auditMode := false
	foundBlockedEvent := false
	for _, e := range regularEvents {
		if e.EventType == events.EventConnectionBlocked || e.EventType == events.EventDNSBlocked || e.EventType == events.EventProtocolBlocked {
			auditMode = e.WouldDeny
			foundBlockedEvent = true
			break
		}
	}
	// Fall back to the --mode flag when no blocked events exist to infer from
	if !foundBlockedEvent {
		auditMode = c.Mode == "audit"
	}

	// Assign events to steps. When step boundaries exist, group causally —
	// each event under the step whose process created its socket — for both
	// the render and the SaaS push, from the same flat event stream and the
	// same assignment rule (assignCausal), so the two can't disagree. Temporal
	// correlation is the legacy fallback for attribution-off runs and old
	// logs, never an intermediate for the causal path.
	var renderGroups, pushGroups []StepEvents
	if len(stepBoundaries) > 0 {
		renderGroups = causalGroups(regularEvents, steps, ordinalSteps)
		pushGroups = buildCausalPushGroups(regularEvents, steps, ordinalSteps)
	} else {
		temporal := c.correlateEventsToSteps(regularEvents, steps)
		deduplicateStepEvents(temporal)
		renderGroups, pushGroups = temporal, temporal
	}

	// Best-effort API push before summary so the link is available for the header
	var workflowRunLink string
	if c.ApiUrl != "" {
		var err error
		workflowRunLink, err = c.pushToApi(pushGroups, steps, regularEvents)
		if err != nil {
			slog.Warn("Best-effort API push failed", "error", err)
		}
	}

	// Generate summary
	c.generateSummary(summaryData{
		groups:          renderGroups,
		rawEvents:       regularEvents,
		existingConn:    existingConnEvents,
		stepBoundaries:  stepBoundaries,
		steps:           steps,
		ordinalSteps:    ordinalSteps,
		auditMode:       auditMode,
		workflowRunLink: workflowRunLink,
	})

	return nil
}

func (c *SummaryCmd) readAuditLog() ([]events.AuditEvent, error) {
	file, err := os.Open(c.AuditLog)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// No audit log at all — e.g. the action ran `start` without
			// --audit-log (audit-summary: false). The push must still
			// happen: the job record, effective mode, status, version, and
			// any downgrade record are independent of event collection, and
			// dropping them made every audit-summary:false job invisible to
			// the dashboard.
			slog.Info("Audit log absent — proceeding with zero events", "path", c.AuditLog)
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var allEvents []events.AuditEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event events.AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue // Skip malformed lines
		}
		allEvents = append(allEvents, event)
	}

	return allEvents, scanner.Err()
}

// reconcileLateAllowedBlocks drops connection_blocked events superseded by a
// connection_late_allowed event for the same (dst_ip, dst_port, protocol) at
// the same time or later. The daemon emits such events when the firewall
// opens for an IP after it was blocked — either in-band (the blocked event's
// hostname matched an allow rule) or via late-allow reconciliation when the
// address records finally traverse the DNS proxy (#83). The policy outcome
// for those attempts is allow, so shipping the block rows to the SaaS as
// denies would fail the check on connections that actually succeeded on
// retry. Blocked events AFTER the latest late-allow for a tuple are kept:
// they represent the destination being blocked again (e.g. a conflicting
// per-port grant), not a superseded retry.
func reconcileLateAllowedBlocks(auditEvents []events.AuditEvent) []events.AuditEvent {
	type connKey struct {
		ip       string
		port     uint16
		protocol string
	}
	latestLateAllow := make(map[connKey]time.Time)
	for _, e := range auditEvents {
		if e.EventType != events.EventConnectionLateAllowed || e.DstIP == "" {
			continue
		}
		k := connKey{ip: e.DstIP, port: e.DstPort, protocol: e.Protocol}
		if e.Timestamp.After(latestLateAllow[k]) {
			latestLateAllow[k] = e.Timestamp
		}
	}
	if len(latestLateAllow) == 0 {
		return auditEvents
	}

	kept := make([]events.AuditEvent, 0, len(auditEvents))
	for _, e := range auditEvents {
		if e.EventType == events.EventConnectionBlocked {
			ts, ok := latestLateAllow[connKey{ip: e.DstIP, port: e.DstPort, protocol: e.Protocol}]
			if ok && !e.Timestamp.After(ts) {
				continue
			}
		}
		kept = append(kept, e)
	}
	return kept
}

// backfillStepCompletion fills null completed_at values (GitHub reports null
// for the in-progress step — always the case for the job's own final steps —
// and API eventual consistency can lag others) from the next step's start,
// or just past the last event for the final step. Mutates steps in place.
// Run calls it for BOTH grouping paths: the SaaS push ships these
// timestamps per step, so the causal path needs the backfill as much as the
// temporal one (which additionally uses the windows for event assignment).
func backfillStepCompletion(steps []GitHubStep, auditEvents []events.AuditEvent) {
	var maxEventTime time.Time
	for _, e := range auditEvents {
		if e.Timestamp.After(maxEventTime) {
			maxEventTime = e.Timestamp
		}
	}
	for i := range steps {
		if steps[i].CompletedAt.IsZero() && !steps[i].StartedAt.IsZero() {
			// Infer from next step's started_at
			if i+1 < len(steps) && !steps[i+1].StartedAt.IsZero() {
				steps[i].CompletedAt = steps[i+1].StartedAt
			} else if !maxEventTime.IsZero() {
				// Last step: extend to cover all events
				steps[i].CompletedAt = maxEventTime.Add(time.Second)
			}
		}
	}
}

func (c *SummaryCmd) correlateEventsToSteps(auditEvents []events.AuditEvent, steps []GitHubStep) []StepEvents {
	// GitHub API returns step timestamps with second precision, but audit events
	// use time.Now() with sub-second precision. Fix up step boundaries so events
	// aren't silently dropped at second boundaries. Idempotent when Run has
	// already backfilled; kept here because tests call this directly.
	backfillStepCompletion(steps, auditEvents)

	// Create step events map keyed by index to handle duplicate step names
	stepEventsMap := make(map[int]*StepEvents)
	for i, step := range steps {
		stepEventsMap[i] = &StepEvents{Step: step}
	}

	// Also track events that don't match any step
	var unmatchedEvents []events.AuditEvent

	// Assign events to steps based on timestamp.
	// Extend each step's completed_at by 1 second to account for the fact that
	// GitHub API timestamps have only second precision, while audit events have
	// sub-second precision. Without this, an event at 22:05:41.500 would miss
	// a step with completed_at=22:05:41.000. Steps are checked in order and
	// first match wins, so the overlap with the next step is harmless.
	for _, event := range auditEvents {
		matched := false
		for i, step := range steps {
			if !step.StartedAt.IsZero() && !step.CompletedAt.IsZero() {
				stepEnd := step.CompletedAt.Add(time.Second)
				// Cap at next step's start to prevent stealing events from the next step
				if i+1 < len(steps) && !steps[i+1].StartedAt.IsZero() && stepEnd.After(steps[i+1].StartedAt) {
					// Only cap if it doesn't create a zero-width window
					if steps[i+1].StartedAt.After(step.StartedAt) {
						stepEnd = steps[i+1].StartedAt
					}
					// else: consecutive steps share the same start time — leave uncapped,
					// first-match-wins handles the overlap correctly
				}
				if !event.Timestamp.Before(step.StartedAt) && event.Timestamp.Before(stepEnd) {
					stepEventsMap[i].Events = append(stepEventsMap[i].Events, event)
					matched = true
					break
				}
			}
		}
		if !matched {
			unmatchedEvents = append(unmatchedEvents, event)
		}
	}

	// Build result preserving step order — include ALL steps (even empty ones)
	var result []StepEvents
	for i := range steps {
		result = append(result, *stepEventsMap[i])
	}

	// Add unmatched events as "Unknown Step"
	if len(unmatchedEvents) > 0 {
		result = append(result, StepEvents{
			Step:   GitHubStep{Name: "Unknown Step (events outside step boundaries)"},
			Events: unmatchedEvents,
		})
	}

	return result
}

type dedupKey struct {
	process   string
	dest      string
	port      uint16
	protocol  string
	eventType events.AuditEventType
}

// backfillDistinguishingFields keeps one row per destination while preserving
// distinguishing fields carried only by a later duplicate (e.g. a CNAME chain
// or auto-allowed type — see issue #77). Only empty fields on the retained
// representative are filled; a value already present is authoritative.
// MatchedRule needs no backfill: only connection_late_allowed events carry it,
// and they always do, so with eventType in the dedup key a same-key group is
// uniformly populated or uniformly empty.
func backfillDistinguishingFields(rep, dup *events.AuditEvent) {
	if len(rep.CNAMEChain) == 0 && len(dup.CNAMEChain) > 0 {
		rep.CNAMEChain = dup.CNAMEChain
	}
	if rep.AutoAllowedType == "" && dup.AutoAllowedType != "" {
		rep.AutoAllowedType = dup.AutoAllowedType
	}
}

func deduplicateStepEvents(stepEvents []StepEvents) {
	for i := range stepEvents {
		seen := make(map[dedupKey]int) // key -> index into deduped
		var deduped []events.AuditEvent
		for _, event := range stepEvents[i].Events {
			dest := event.DstHostname
			if dest == "" {
				dest = event.DstIP
			}
			key := dedupKey{process: event.Process, dest: dest, port: event.DstPort, protocol: event.Protocol, eventType: event.EventType}
			if idx, exists := seen[key]; exists {
				backfillDistinguishingFields(&deduped[idx], &event)
				continue
			}
			seen[key] = len(deduped)
			deduped = append(deduped, event)
		}
		stepEvents[i].Events = deduped
	}
}

func computeSummary(allEvents []events.AuditEvent, mode data.CargoWallMode) *cargowallv1.CargoWallActionJobSummary {
	var allowed, blocked, autoAllowed uint32
	hostnames := make(map[string]struct{})
	for _, e := range allEvents {
		switch e.EventType {
		case events.EventConnectionAllowed, events.EventConnectionLateAllowed:
			allowed++
			if e.AutoAllowedType != "" {
				autoAllowed++
			}
		case events.EventConnectionBlocked, events.EventDNSBlocked, events.EventProtocolBlocked:
			blocked++
		}
		if e.DstHostname != "" {
			hostnames[e.DstHostname] = struct{}{}
		}
	}

	var denied, wouldDeny uint32
	if mode == data.CargoWallMode_CARGO_WALL_MODE_AUDIT {
		wouldDeny = blocked
	} else {
		denied = blocked
	}

	return &cargowallv1.CargoWallActionJobSummary{
		TotalConnections:       allowed + blocked,
		AllowedConnections:     allowed,
		DeniedConnections:      denied,
		WouldDenyConnections:   wouldDeny,
		UniqueHostnames:        uint32(len(hostnames)),
		AutoAllowedConnections: autoAllowed,
	}
}

// rawEvents is the PRE-dedup event stream; the job window is computed from
// it because the grouped events have already been deduplicated (first
// occurrence kept), so their max timestamp would end the window at the
// first retry of the last destination rather than the job's real last
// network activity. Nil falls back to the grouped events (legacy callers).
func (c *SummaryCmd) pushToApi(stepEvents []StepEvents, steps []GitHubStep, rawEvents []events.AuditEvent) (string, error) {
	if c.Token == "" {
		return "", fmt.Errorf("no token provided, skipping API push")
	}
	if c.JobName == "" {
		return "", fmt.Errorf("no job-name provided, skipping API push")
	}

	// Map mode string to proto enum
	mode := data.CargoWallMode_CARGO_WALL_MODE_ENFORCE
	switch c.Mode {
	case "audit":
		mode = data.CargoWallMode_CARGO_WALL_MODE_AUDIT
	case "enforce":
		mode = data.CargoWallMode_CARGO_WALL_MODE_ENFORCE
	}

	// Map default-action string to proto enum
	defaultAction := data.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY
	switch c.DefaultAction {
	case "allow":
		defaultAction = data.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW
	case "deny":
		defaultAction = data.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY
	}

	// Map job-status string to proto enum
	jobStatus := data.CargoWallJobStatus_CARGO_WALL_JOB_STATUS_UNSPECIFIED
	switch c.JobStatus {
	case "success":
		jobStatus = data.CargoWallJobStatus_CARGO_WALL_JOB_STATUS_SUCCESS
	case "failure":
		jobStatus = data.CargoWallJobStatus_CARGO_WALL_JOB_STATUS_FAILURE
	case "cancelled":
		fallthrough
	case "canceled":
		jobStatus = data.CargoWallJobStatus_CARGO_WALL_JOB_STATUS_CANCELED
	case "timed_out":
		jobStatus = data.CargoWallJobStatus_CARGO_WALL_JOB_STATUS_TIMED_OUT
	}

	// Build steps with events
	var protoSteps []*cargowallv1.CreateCargoWallActionStep
	var allEvents []events.AuditEvent

	if stepEvents != nil {
		for i, se := range stepEvents {
			step := &cargowallv1.CreateCargoWallActionStep{
				Name:   se.Step.Name,
				Number: int32(i + 1),
			}
			if !se.Step.StartedAt.IsZero() {
				step.StartedAt = timestamppb.New(se.Step.StartedAt)
			}
			if !se.Step.CompletedAt.IsZero() {
				step.CompletedAt = timestamppb.New(se.Step.CompletedAt)
			}

			for _, e := range se.Events {
				protoEvent := auditEventToProto(e)
				step.Events = append(step.Events, protoEvent)
				allEvents = append(allEvents, e)
			}

			protoSteps = append(protoSteps, step)
		}
	} else {
		// No step events (empty audit log) — use steps from the GitHub API
		for i, s := range steps {
			step := &cargowallv1.CreateCargoWallActionStep{
				Name:   s.Name,
				Number: int32(i + 1),
			}
			if !s.StartedAt.IsZero() {
				step.StartedAt = timestamppb.New(s.StartedAt)
			}
			if !s.CompletedAt.IsZero() {
				step.CompletedAt = timestamppb.New(s.CompletedAt)
			}
			protoSteps = append(protoSteps, step)
		}
	}

	summary := computeSummary(allEvents, mode)

	req := &cargowallv1.CreateCargoWallActionJobRequest{
		JobName:       c.JobName,
		JobKey:        c.JobKey,
		Mode:          mode,
		DefaultAction: defaultAction,
		Steps:         protoSteps,
		Summary:       summary,
		Status:        jobStatus,
	}

	if c.JobRunId != 0 {
		req.JobRunId = &c.JobRunId
	}

	if c.Version != "" {
		req.Version = &c.Version
	}

	// Carry the downgrade record left by `cargowall start` (a separate
	// process invocation) so the dashboard can badge degraded runs and
	// count them by type/failure class.
	req.Downgrade = readDowngrade()

	// Job window from the extreme event timestamps. Min/max, not first and
	// last: causal grouping orders events by step (scaffold first, buckets
	// appended), so positional endpoints could invert the window — e.g. one
	// pre-daemon bucket event flattening after the last scaffold step would
	// send started_at after completed_at. Over the raw stream when the
	// caller provided it — see the rawEvents doc above.
	window := rawEvents
	if window == nil {
		window = allEvents
	}
	if len(window) > 0 {
		first, last := window[0].Timestamp, window[0].Timestamp
		for _, e := range window[1:] {
			if e.Timestamp.Before(first) {
				first = e.Timestamp
			}
			if e.Timestamp.After(last) {
				last = e.Timestamp
			}
		}
		req.StartedAt = timestamppb.New(first)
		req.CompletedAt = timestamppb.New(last)
	}

	// Marshal using protojson for HTTP/JSON transcoding compatibility
	marshaler := protojson.MarshalOptions{UseProtoNames: true}
	jsonBytes, err := marshaler.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal API request: %w", err)
	}

	url := strings.TrimRight(c.ApiUrl, "/") + "/api/cargowall/v1/action/job"
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(jsonBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.Token)

	// Bounded like the policy fetch: api-url is user-supplied, and a hung
	// endpoint would otherwise block the post step until the job timeout,
	// losing the summary push entirely.
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to push audit results to API: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxPolicyResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned non-OK status %d: %s", resp.StatusCode, truncateForError(body))
	}

	var result cargowallv1.CreateCargoWallActionJobResponse
	// DiscardUnknown so additive response fields from a newer controller are
	// tolerated. A genuine parse failure is returned so the caller's best-effort
	// warning fires (the push itself already succeeded; we just lack the link).
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse API push response %q: %w", string(body), err)
	}

	slog.Info("Audit results pushed to API",
		"job_id", result.JobId,
		"workflow_run_id", result.WorkflowRunId,
		"workflow_run_link", result.WorkflowRunUrl)
	return result.WorkflowRunUrl, nil
}

// readDowngrade returns the downgrade record written by `cargowall start`,
// or nil when the run executed at its requested posture (file absent).
// Best-effort by design: a corrupt record is dropped rather than failing
// the push, but leaves a trace for the day a downgrade mysteriously never
// reaches the dashboard.
func readDowngrade() *cargowallv1.CargoWallDowngrade {
	// Read defensively like the sentinel readers: the path is fixed and
	// world-writable, so a planted symlink (e.g. to /dev/zero) or an
	// oversized file must not be followed or slurped.
	sf, ok := readStateFile(downgradeFile)
	if !ok {
		return nil
	}
	var d cargowallv1.CargoWallDowngrade
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(sf.data, &d); err != nil {
		slog.Debug("Downgrade record unreadable — omitting from push", "path", downgradeFile, "error", err)
		return nil
	}
	return &d
}

// auditEventToProto converts one audit event to the wire type.
//
// StepOrdinal is deliberately NOT sent: ordinals are run-local counters, so
// they carry no meaning the server can act on across runs. Causal
// attribution reaches the SaaS through the grouping instead — each event
// ships under the step its ordinal resolved to. When the server needs step
// identity it can key on (per-step policy), that will be the stable YAML
// step `id:`, added to the schema then rather than a counter now.
func auditEventToProto(e events.AuditEvent) *cargowallv1.CargoWallActionEvent {
	actionType := data.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW
	switch e.EventType {
	case events.EventConnectionBlocked, events.EventDNSBlocked, events.EventProtocolBlocked:
		actionType = data.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY
	}

	category := data.CargoWallEventCategory_CARGO_WALL_EVENT_CATEGORY_UNSPECIFIED
	switch e.EventType {
	case events.EventDNSBlocked:
		category = data.CargoWallEventCategory_CARGO_WALL_EVENT_CATEGORY_DNS
	case events.EventConnectionBlocked, events.EventConnectionAllowed, events.EventConnectionLateAllowed, events.EventExistingConnection:
		category = data.CargoWallEventCategory_CARGO_WALL_EVENT_CATEGORY_CONNECTION
	case events.EventProtocolBlocked:
		category = data.CargoWallEventCategory_CARGO_WALL_EVENT_CATEGORY_PROTOCOL
	}

	event := &cargowallv1.CargoWallActionEvent{
		Timestamp: timestamppb.New(e.Timestamp),
		Action:    actionType,
		Category:  category,
	}
	if e.DstHostname != "" {
		event.Hostname = &e.DstHostname
	}
	if e.DstIP != "" {
		event.Ip = &e.DstIP
	}
	if e.DstPort != 0 {
		port := uint32(e.DstPort)
		event.Port = &port
	}
	if e.Protocol != "" {
		event.Protocol = &e.Protocol
	}
	if e.MatchedRule != "" {
		event.MatchedRule = &e.MatchedRule
	}
	if e.Process != "" {
		event.Process = &e.Process
	}
	if e.AutoAllowedType != "" {
		if autoType, ok := mapAutoAllowedType(e.AutoAllowedType); ok {
			event.AutoAllowedType = &autoType
		}
	}
	if len(e.CNAMEChain) > 0 {
		event.CnameChain = e.CNAMEChain
	}
	return event
}

// mapAutoAllowedType converts an internal AutoAddedType string to the proto
// enum used by the SaaS API push. Unrecognized types return ok=false, which
// causes the caller to omit the AutoAllowedType field on the pushed event.
func mapAutoAllowedType(s string) (data.CargoWallAutoAllowedType, bool) {
	switch s {
	case "dns":
		return data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_DNS, true
	case "cloud_metadata":
		return data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_CLOUD_METADATA, true
	case "azure_infrastructure":
		return data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_AZURE_INFRASTRUCTURE, true
	case "github_service":
		return data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_GITHUB_SERVICE, true
	case "gitlab_service":
		return data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_GITLAB_SERVICE, true
	case "codecargo_service":
		return data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_CODECARGO_SERVICE, true
	default:
		return data.CargoWallAutoAllowedType_CARGO_WALL_AUTO_ALLOWED_TYPE_UNSPECIFIED, false
	}
}
