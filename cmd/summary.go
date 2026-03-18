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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
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
	AuditLog string `help:"Path to audit log JSON file" required:""`
	Steps    string `help:"JSON array of step timing from GitHub API" required:""`

	// API push flags (optional — skip API push if api-url is not set)
	ApiUrl        string `help:"CodeCargo API URL for pushing results" name:"api-url"`
	Token         string `help:"OIDC bearer token for API authentication"`
	JobName       string `help:"GitHub Actions job name" name:"job-name"`
	JobKey        string `help:"GitHub Actions job key (github.job)" name:"job-key"`
	Mode          string `help:"CargoWall mode (enforce/audit)"`
	DefaultAction string `help:"Default action type (allow/deny)" name:"default-action"`
	JobStatus     string `help:"GitHub Actions job status (success/failure/canceled/cancelled/timed_out)" name:"job-status"`
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

	if len(auditEvents) == 0 {
		// Best-effort API push — log warning on failure but don't fail the summary
		var workflowRunLink string
		if c.ApiUrl != "" {
			var err error
			workflowRunLink, err = c.pushToApi(nil, steps)
			if err != nil {
				slog.Warn("Best-effort API push failed", "error", err)
			}
		}

		if workflowRunLink != "" {
			fmt.Printf("## CargoWall Network Audit ([view on CodeCargo](%s))\n", workflowRunLink)
		} else {
			fmt.Println("## CargoWall Network Audit")
		}
		fmt.Println()
		fmt.Println("No network events were logged during this workflow run.")
		return nil
	}

	// Separate existing connection events from regular events
	var existingConnEvents, regularEvents []events.AuditEvent
	for _, event := range auditEvents {
		if event.EventType == events.EventExistingConnection {
			existingConnEvents = append(existingConnEvents, event)
		} else {
			regularEvents = append(regularEvents, event)
		}
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

	// Correlate events to steps (includes all steps, even empty ones)
	stepEvents := c.correlateEventsToSteps(regularEvents, steps)
	deduplicateStepEvents(stepEvents)

	// Best-effort API push before summary so the link is available for the header
	var workflowRunLink string
	if c.ApiUrl != "" {
		var err error
		workflowRunLink, err = c.pushToApi(stepEvents, steps)
		if err != nil {
			slog.Warn("Best-effort API push failed", "error", err)
		}
	}

	// Generate summary
	c.generateSummary(stepEvents, existingConnEvents, auditMode, workflowRunLink)

	return nil
}

func (c *SummaryCmd) readAuditLog() ([]events.AuditEvent, error) {
	file, err := os.Open(c.AuditLog)
	if err != nil {
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

func (c *SummaryCmd) correlateEventsToSteps(auditEvents []events.AuditEvent, steps []GitHubStep) []StepEvents {
	// GitHub API returns step timestamps with second precision, but audit events
	// use time.Now() with sub-second precision. Fix up step boundaries so events
	// aren't silently dropped at second boundaries.
	//
	// Also handle steps with null completed_at (in-progress or API eventual
	// consistency) by inferring the end time from the next step's started_at.
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
	eventType events.AuditEventType
}

func deduplicateStepEvents(stepEvents []StepEvents) {
	for i, se := range stepEvents {
		seen := make(map[dedupKey]struct{})
		var deduped []events.AuditEvent
		for _, event := range se.Events {
			dest := event.DstHostname
			if dest == "" {
				dest = event.DstIP
			}
			key := dedupKey{process: event.Process, dest: dest, port: event.DstPort, eventType: event.EventType}
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				deduped = append(deduped, event)
			}
		}
		stepEvents[i].Events = deduped
	}
}

func (c *SummaryCmd) generateSummary(stepEvents []StepEvents, existingConnEvents []events.AuditEvent, auditMode bool, workflowRunLink string) {
	// Count totals
	var totalBlocked, totalConnectionsAllowed, totalDNSBlocked, totalProtocolBlocked int
	for _, se := range stepEvents {
		for _, event := range se.Events {
			switch event.EventType {
			case events.EventConnectionBlocked:
				totalBlocked++
			case events.EventConnectionAllowed:
				totalConnectionsAllowed++
			case events.EventProtocolBlocked:
				totalProtocolBlocked++
			case events.EventDNSBlocked:
				totalDNSBlocked++
			}
		}
	}

	// Print header
	linkSuffix := ""
	if workflowRunLink != "" {
		linkSuffix = fmt.Sprintf(" ([view on CodeCargo](%s))", workflowRunLink)
	}
	if auditMode {
		fmt.Printf("## CargoWall Network Audit (Audit Mode - No Blocking)%s\n", linkSuffix)
		fmt.Println()
		fmt.Println("> Running in audit mode. Connections shown below were **logged but NOT blocked**.")
		fmt.Println("> Switch to `mode: enforce` to block these connections.")
	} else {
		fmt.Printf("## CargoWall Network Audit (Enforce Mode)%s\n", linkSuffix)
	}
	fmt.Println()

	// Print summary table
	fmt.Println("### Summary")
	fmt.Println("| Metric | Count |")
	fmt.Println("|--------|-------|")
	if auditMode {
		fmt.Printf("| Connections that would be denied | %d |\n", totalBlocked)
		fmt.Printf("| Protocols that would be denied | %d |\n", totalProtocolBlocked)
		fmt.Printf("| DNS queries that would be denied | %d |\n", totalDNSBlocked)
	} else {
		fmt.Printf("| Connections blocked | %d |\n", totalBlocked)
		fmt.Printf("| Protocols blocked | %d |\n", totalProtocolBlocked)
		fmt.Printf("| DNS queries blocked | %d |\n", totalDNSBlocked)
	}
	fmt.Printf("| Connections allowed | %d |\n", totalConnectionsAllowed)
	if len(existingConnEvents) > 0 {
		fmt.Printf("| Pre-existing connections | %d |\n", len(existingConnEvents))
	}
	fmt.Println()

	// Print pre-existing connections section if any
	if len(existingConnEvents) > 0 {
		c.generateExistingConnectionsSection(existingConnEvents)
	}

	// Print events by step (only steps with events for the markdown summary)
	fmt.Println("### Events by Step")
	fmt.Println()

	for _, se := range stepEvents {
		if len(se.Events) == 0 {
			continue
		}

		timeRange := ""
		if !se.Step.StartedAt.IsZero() && !se.Step.CompletedAt.IsZero() {
			timeRange = fmt.Sprintf(" (%s - %s)",
				se.Step.StartedAt.Format("15:04:05"),
				se.Step.CompletedAt.Format("15:04:05"))
		}
		fmt.Printf("#### Step: \"%s\"%s\n", se.Step.Name, timeRange)
		fmt.Println()

		// Build unique entries keyed by (destination, event_type, process)
		type entryKey struct {
			dest      string
			eventType events.AuditEventType
			process   string
		}
		type summaryEntry struct {
			dest      string
			typeLabel string
			blocked   bool
			process   string
		}

		entries := make(map[entryKey]*summaryEntry)
		var sorted []*summaryEntry
		for _, event := range se.Events {
			dest := c.eventDestination(event)
			key := entryKey{dest: dest, eventType: event.EventType, process: event.Process}
			if _, ok := entries[key]; !ok {
				e := &summaryEntry{
					dest:      dest,
					typeLabel: c.eventTypeLabel(event.EventType),
					blocked:   event.EventType != events.EventConnectionAllowed,
					process:   event.Process,
				}
				entries[key] = e
				sorted = append(sorted, e)
			}
		}

		// Sort: blocked first, then alphabetically by destination
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].blocked != sorted[j].blocked {
				return sorted[i].blocked
			}
			return sorted[i].dest < sorted[j].dest
		})

		if len(sorted) > 0 {
			fmt.Println("| Destination | Type | Status | Process |")
			fmt.Println("|-------------|------|--------|---------|")
			for _, e := range sorted {
				var status string
				if e.blocked {
					if auditMode {
						status = ":warning: Would deny"
					} else {
						status = ":x: Blocked"
					}
				} else {
					status = ":white_check_mark: Allowed"
				}
				process := e.process
				if process == "" {
					process = "-"
				}
				fmt.Printf("| %s | %s | %s | %s |\n", e.dest, e.typeLabel, status, process)
			}
			fmt.Println()
		} else {
			fmt.Println("No network events recorded")
			fmt.Println()
		}
	}

	// In audit mode, suggest allowlist additions
	if auditMode && (totalBlocked > 0 || totalDNSBlocked > 0) {
		c.generateAllowlistSuggestions(stepEvents)
	}
}

func computeSummary(allEvents []events.AuditEvent, mode data.CargoWallMode) *cargowallv1.CargoWallActionJobSummary {
	var allowed, blocked uint32
	hostnames := make(map[string]struct{})
	for _, e := range allEvents {
		switch e.EventType {
		case events.EventConnectionAllowed:
			allowed++
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
		TotalConnections:     allowed + blocked,
		AllowedConnections:   allowed,
		DeniedConnections:    denied,
		WouldDenyConnections: wouldDeny,
		UniqueHostnames:      uint32(len(hostnames)),
	}
}

func (c *SummaryCmd) pushToApi(stepEvents []StepEvents, steps []GitHubStep) (string, error) {
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

	// Set timestamps from first/last events
	if len(allEvents) > 0 {
		req.StartedAt = timestamppb.New(allEvents[0].Timestamp)
		req.CompletedAt = timestamppb.New(allEvents[len(allEvents)-1].Timestamp)
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

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to push audit results to API: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned non-OK status %d: %s", resp.StatusCode, string(body))
	}

	var result cargowallv1.CreateCargoWallActionJobResponse
	if err := protojson.Unmarshal(body, &result); err != nil {
		slog.Info("Audit results pushed to API", "response", string(body))
		return "", nil
	}

	slog.Info("Audit results pushed to API",
		"job_id", result.JobId,
		"workflow_run_id", result.WorkflowRunId,
		"workflow_run_link", result.WorkflowRunUrl)
	return result.WorkflowRunUrl, nil
}

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
	case events.EventConnectionBlocked, events.EventConnectionAllowed, events.EventExistingConnection:
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
	return event
}

func (c *SummaryCmd) eventDestination(event events.AuditEvent) string {
	// Protocol blocks (ICMP, GRE, etc.) show as "hostname (PROTOCOL)" or "IP (PROTOCOL)"
	if event.EventType == events.EventProtocolBlocked {
		dest := event.DstHostname
		if dest == "" {
			dest = event.DstIP
		}
		return fmt.Sprintf("%s (%s)", dest, event.Protocol)
	}
	dest := event.DstHostname
	if dest == "" {
		dest = event.DstIP
	}
	if event.DstPort > 0 {
		dest = fmt.Sprintf("%s:%d", dest, event.DstPort)
	}
	return dest
}

func (c *SummaryCmd) eventTypeLabel(eventType events.AuditEventType) string {
	switch eventType {
	case events.EventConnectionBlocked:
		return "Connection"
	case events.EventConnectionAllowed:
		return "Connection"
	case events.EventProtocolBlocked:
		return "Protocol"
	case events.EventDNSBlocked:
		return "DNS"
	default:
		return string(eventType)
	}
}

func (c *SummaryCmd) generateAllowlistSuggestions(stepEvents []StepEvents) {
	// Count occurrences of each destination
	destCounts := make(map[string]int)
	for _, se := range stepEvents {
		for _, event := range se.Events {
			if event.EventType == events.EventConnectionBlocked || event.EventType == events.EventDNSBlocked {
				dest := event.DstHostname
				if dest == "" {
					dest = event.DstIP
				}
				destCounts[dest]++
			}
		}
	}

	if len(destCounts) == 0 {
		return
	}

	// Sort by count descending
	type destCount struct {
		dest  string
		count int
	}
	var sorted []destCount
	for dest, count := range destCounts {
		sorted = append(sorted, destCount{dest, count})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	fmt.Println("### Recommended Allowlist Additions")
	fmt.Println("Based on this audit, consider adding these hosts if they are legitimate:")
	fmt.Println()
	for _, dc := range sorted {
		attempts := "attempt"
		if dc.count > 1 {
			attempts = "attempts"
		}
		fmt.Printf("- `%s` (%d connection %s)\n", dc.dest, dc.count, attempts)
	}
	fmt.Println()
	fmt.Println("Add these to your workflow with:")
	fmt.Println("```yaml")
	fmt.Println("- uses: code-cargo/cargowall-action@latest")
	fmt.Println("  with:")
	fmt.Println("    allowed-hosts: |")
	for i, dc := range sorted {
		if i >= 5 {
			fmt.Println("      # ... and more")
			break
		}
		// Check if it looks like an IP
		if strings.Count(dc.dest, ".") == 3 && !strings.Contains(dc.dest, "/") {
			continue // Skip raw IPs in example
		}
		fmt.Printf("      %s\n", dc.dest)
	}
	fmt.Println("```")
}

func (c *SummaryCmd) generateExistingConnectionsSection(existingConnEvents []events.AuditEvent) {
	fmt.Println("### Pre-Existing Connections")
	fmt.Println()
	fmt.Println("These connections were already established when CargoWall started:")
	fmt.Println()
	fmt.Println("| IP | Hostname | Status |")
	fmt.Println("|----|----------|--------|")

	// Sort: connections matching rules first, then by hostname
	sort.Slice(existingConnEvents, func(i, j int) bool {
		// Connections with matched rules come first
		iMatched := existingConnEvents[i].MatchedRule != ""
		jMatched := existingConnEvents[j].MatchedRule != ""
		if iMatched != jMatched {
			return iMatched
		}
		// Within same match status, sort by hostname
		return existingConnEvents[i].DstHostname < existingConnEvents[j].DstHostname
	})

	for _, event := range existingConnEvents {
		ip := event.DstIP
		hostname := event.DstHostname
		if hostname == "" {
			hostname = "-"
		}
		matchedRule := event.MatchedRule

		var status string
		if matchedRule != "" {
			status = fmt.Sprintf(":white_check_mark: Allowed (matches %s)", matchedRule)
		} else {
			status = ":white_check_mark: Allowed"
		}

		fmt.Printf("| %s | %s | %s |\n", ip, hostname, status)
	}
	fmt.Println()
}
