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

// Markdown rendering for the job summary: the metrics table, per-step
// entries tables, allowlist suggestions, pre-existing connections, and the
// table-cell escaping helpers. Data assembly (audit log I/O, correlation,
// dedup) and the SaaS push live in summary.go; causal attribution lives in
// summary_attribution.go.
package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/code-cargo/cargowall/pkg/events"
)

// mdCell neutralizes user-controlled text (workflow step names, process
// command lines, DNS-derived hostnames) for use inside a markdown table
// cell: pipes would add phantom columns, newlines would break the row.
var mdCellReplacer = strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ")

func mdCell(s string) string {
	return mdCellReplacer.Replace(s)
}

// mdCode is mdCell for text rendered inside a code span, where a backtick
// in the value would terminate the span.
var mdCodeReplacer = strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "`", "'")

func mdCode(s string) string {
	return mdCodeReplacer.Replace(s)
}

// summaryData carries everything generateSummary renders. rawEvents are the
// pre-dedup connection/DNS/protocol events, so the metrics table can show
// honest event counts next to the unique-destination counts (TCP retries of
// one blocked curl are 9 events but 1 destination — showing only one number
// made the tables look inconsistent with each other).
type summaryData struct {
	groups          []StepEvents // final render grouping (causal when boundaries exist, else temporal)
	rawEvents       []events.AuditEvent
	existingConn    []events.AuditEvent
	stepBoundaries  []events.AuditEvent
	steps           []GitHubStep
	ordinalSteps    map[uint32]int // step ordinal → index into steps
	auditMode       bool
	workflowRunLink string
}

// tallyEvents counts events by outcome class.
func tallyEvents(evts []events.AuditEvent) (blocked, allowed, dnsBlocked, protoBlocked, autoAllowed int) {
	for _, event := range evts {
		switch event.EventType {
		case events.EventConnectionBlocked:
			blocked++
		case events.EventConnectionAllowed, events.EventConnectionLateAllowed:
			allowed++
			if event.AutoAllowedType != "" {
				autoAllowed++
			}
		case events.EventProtocolBlocked:
			protoBlocked++
		case events.EventDNSBlocked:
			dnsBlocked++
		}
	}
	return
}

func (c *SummaryCmd) generateSummary(d summaryData) {
	auditMode := d.auditMode

	// Grouping is finished in Run: causal (each event under the step whose
	// process created its socket) when boundaries exist, temporal otherwise.
	groups := d.groups
	causal := len(d.stepBoundaries) > 0

	// Unique counts come from the grouping actually rendered; raw counts
	// from the unfiltered event stream.
	var flat []events.AuditEvent
	for _, g := range groups {
		flat = append(flat, g.Events...)
	}
	totalBlocked, totalConnectionsAllowed, totalDNSBlocked, totalProtocolBlocked, totalAutoAllowed := tallyEvents(flat)
	rawEvents := d.rawEvents
	if rawEvents == nil {
		rawEvents = flat
	}
	rawBlocked, rawAllowed, rawDNSBlocked, rawProtoBlocked, rawAutoAllowed := tallyEvents(rawEvents)

	// Print header
	if auditMode {
		fmt.Fprintln(c.output, "## CargoWall (Audit Mode - No Blocking)")
		fmt.Fprintln(c.output)
		fmt.Fprintln(c.output, "> Running in audit mode. Connections shown below were **logged but NOT blocked**.")
		fmt.Fprintln(c.output, "> Switch to `mode: enforce` to block these connections.")
	} else {
		fmt.Fprintln(c.output, "## CargoWall (Enforce Mode)")
	}
	fmt.Fprintln(c.output)

	// When a SaaS link is available, condense output: just header + link
	if d.workflowRunLink != "" {
		fmt.Fprintf(c.output, "[View full details on CodeCargo](%s)\n", d.workflowRunLink)
		return
	}

	// Print summary table. "Unique" counts destination/process rows as
	// rendered below; "Events" counts raw audit records — one blocked curl
	// retransmitting is many events but one destination, and showing only
	// one of the two numbers makes the sections look mutually inconsistent.
	fmt.Fprintln(c.output, "### Summary")
	fmt.Fprintln(c.output, "| Metric | Unique | Events |")
	fmt.Fprintln(c.output, "|--------|--------|--------|")
	if auditMode {
		fmt.Fprintf(c.output, "| Connections that would be denied | %d | %d |\n", totalBlocked, rawBlocked)
		fmt.Fprintf(c.output, "| Protocols that would be denied | %d | %d |\n", totalProtocolBlocked, rawProtoBlocked)
		fmt.Fprintf(c.output, "| DNS queries that would be denied | %d | %d |\n", totalDNSBlocked, rawDNSBlocked)
	} else {
		fmt.Fprintf(c.output, "| Connections blocked | %d | %d |\n", totalBlocked, rawBlocked)
		fmt.Fprintf(c.output, "| Protocols blocked | %d | %d |\n", totalProtocolBlocked, rawProtoBlocked)
		fmt.Fprintf(c.output, "| DNS queries blocked | %d | %d |\n", totalDNSBlocked, rawDNSBlocked)
	}
	fmt.Fprintf(c.output, "| Connections allowed | %d | %d |\n", totalConnectionsAllowed, rawAllowed)
	if totalAutoAllowed > 0 {
		fmt.Fprintf(c.output, "| Auto-allowed connections | %d | %d |\n", totalAutoAllowed, rawAutoAllowed)
	}
	if len(d.existingConn) > 0 {
		fmt.Fprintf(c.output, "| Pre-existing connections | %d | %d |\n", len(d.existingConn), len(d.existingConn))
	}
	fmt.Fprintln(c.output)

	// Print pre-existing connections section if any
	if len(d.existingConn) > 0 {
		c.generateExistingConnectionsSection(d.existingConn)
	}

	// Print events by step (only steps with events for the markdown summary)
	fmt.Fprintln(c.output, "### Events by Step")
	fmt.Fprintln(c.output)
	if causal {
		fmt.Fprintln(c.output, "Grouped causally: each event appears under the step whose process created its socket (see Step Attribution below), not the step that was running when packets flowed.")
		fmt.Fprintln(c.output)
	}

	for _, se := range groups {
		if len(se.Events) == 0 {
			continue
		}

		timeRange := ""
		if !se.Step.StartedAt.IsZero() && !se.Step.CompletedAt.IsZero() {
			timeRange = fmt.Sprintf(" (%s - %s)",
				se.Step.StartedAt.Format("15:04:05"),
				se.Step.CompletedAt.Format("15:04:05"))
		}
		fmt.Fprintf(c.output, "#### Step: \"%s\"%s\n", mdCell(se.Step.Name), timeRange)
		fmt.Fprintln(c.output)

		// Build unique entries keyed by (destination, event_type, process)
		type entryKey struct {
			dest        string
			eventType   events.AuditEventType
			process     string
			stepOrdinal uint32
		}
		type summaryEntry struct {
			dest        string
			typeLabel   string
			blocked     bool
			autoAllowed bool
			process     string
			stepLabel   string
		}

		entries := make(map[entryKey]*summaryEntry)
		var sorted []*summaryEntry
		for _, event := range se.Events {
			dest := c.eventDestination(event)
			key := entryKey{dest: dest, eventType: event.EventType, process: event.Process, stepOrdinal: event.StepOrdinal}
			if _, ok := entries[key]; !ok {
				e := &summaryEntry{
					dest:        dest,
					typeLabel:   c.eventTypeLabel(event.EventType),
					blocked:     !event.EventType.IsConnectionAllowed(),
					autoAllowed: event.AutoAllowedType != "",
					process:     event.Process,
					stepLabel:   stepOrdinalLabel(event.StepOrdinal),
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
			fmt.Fprintln(c.output, "| Destination | Type | Status | Process | Step |")
			fmt.Fprintln(c.output, "|-------------|------|--------|---------|------|")
			for _, e := range sorted {
				var status string
				if e.blocked {
					if auditMode {
						status = ":warning: Would deny"
					} else {
						status = ":x: Blocked"
					}
				} else if e.autoAllowed {
					status = ":white_check_mark: Allowed (auto)"
				} else {
					status = ":white_check_mark: Allowed"
				}
				process := e.process
				if process == "" {
					process = "-"
				}
				fmt.Fprintf(c.output, "| %s | %s | %s | %s | %s |\n", mdCell(e.dest), e.typeLabel, status, mdCell(process), e.stepLabel)
			}
			fmt.Fprintln(c.output)
		} else {
			fmt.Fprintln(c.output, "No network events recorded")
			fmt.Fprintln(c.output)
		}
	}

	c.generateStepAttributionSection(d.stepBoundaries, d.steps, d.ordinalSteps)

	// In audit mode, suggest allowlist additions
	if auditMode && (totalBlocked > 0 || totalDNSBlocked > 0) {
		c.generateAllowlistSuggestions(groups)
	}
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
	case events.EventConnectionBlocked, events.EventConnectionAllowed, events.EventConnectionLateAllowed:
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

	fmt.Fprintln(c.output, "### Recommended Allowlist Additions")
	fmt.Fprintln(c.output, "Based on this audit, consider adding these hosts if they are legitimate:")
	fmt.Fprintln(c.output)
	for _, dc := range sorted {
		attempts := "attempt"
		if dc.count > 1 {
			attempts = "attempts"
		}
		fmt.Fprintf(c.output, "- `%s` (%d connection %s)\n", dc.dest, dc.count, attempts)
	}
	fmt.Fprintln(c.output)
	fmt.Fprintln(c.output, "Add these to your workflow with:")
	fmt.Fprintln(c.output, "```yaml")
	fmt.Fprintln(c.output, "- uses: code-cargo/cargowall-action@latest")
	fmt.Fprintln(c.output, "  with:")
	fmt.Fprintln(c.output, "    allowed-hosts: |")
	for i, dc := range sorted {
		if i >= 5 {
			fmt.Fprintln(c.output, "      # ... and more")
			break
		}
		// Check if it looks like an IP
		if strings.Count(dc.dest, ".") == 3 && !strings.Contains(dc.dest, "/") {
			continue // Skip raw IPs in example
		}
		fmt.Fprintf(c.output, "      %s\n", dc.dest)
	}
	fmt.Fprintln(c.output, "```")
}

func (c *SummaryCmd) generateExistingConnectionsSection(existingConnEvents []events.AuditEvent) {
	fmt.Fprintln(c.output, "### Pre-Existing Connections")
	fmt.Fprintln(c.output)
	fmt.Fprintln(c.output, "These connections were already established when CargoWall started:")
	fmt.Fprintln(c.output)
	fmt.Fprintln(c.output, "| IP | Hostname | Status |")
	fmt.Fprintln(c.output, "|----|----------|--------|")

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

		fmt.Fprintf(c.output, "| %s | %s | %s |\n", ip, hostname, status)
	}
	fmt.Fprintln(c.output)
}
