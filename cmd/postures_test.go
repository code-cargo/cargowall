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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/code-cargo/cargowall/pkg/origin"
	"github.com/code-cargo/cargowall/pkg/steps"
)

// verifierTooLarge is the error shape origin.Start returned on the 6.6
// Blacksmith runner: cilium's wrapping names the program, the verifier log
// carries the count.
func verifierTooLarge() error {
	return fmt.Errorf("failed to load origin BPF objects: program cg_origin_egress: load program: %w",
		&ebpf.VerifierError{Cause: unix.E2BIG, Log: []string{"BPF program is too large. Processed 1000001 insn"}})
}

func ledgerWithLog(t *testing.T, egress, sni string) (*postureLedger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cmd := &StartCmd{ContainerEgress: egress, TLSSNI: sni}
	return newPostures(cmd, "6.6.141", slog.New(slog.NewTextHandler(&buf, nil))), &buf
}

// public strips the in-memory registration fields, leaving what the file
// carries.
func public(recs []postureRecord) []postureRecord {
	out := make([]postureRecord, len(recs))
	for i, r := range recs {
		out[i] = postureRecord{Posture: r.Posture, Requested: r.Requested, Applied: r.Applied, Reason: r.Reason}
	}
	return out
}

func TestPostures_OffLayersAreNotTracked(t *testing.T) {
	p, _ := ledgerWithLog(t, ContainerEgressOff, TLSSNIOff)
	assert.Empty(t, p.records)

	p, _ = ledgerWithLog(t, ContainerEgressObserve, TLSSNIOff)
	assert.Equal(t, []postureRecord{{Posture: postureContainerEgress, Requested: "observe", Applied: "observe"}}, public(p.records))
}

// Every rung that promises drops is fail-closed, each checked against its
// own flag: a lost one is a startup error naming the flag and the reason —
// the text the failure sentinel carries to the action — and the record is
// marked lost too, so it agrees with the sentinel whoever publishes it.
func TestPostures_LostEnforceFailsStartup(t *testing.T) {
	for _, tc := range []struct {
		egress, sni, lose, reason, want string
	}{
		{
			ContainerEgressEnforce, TLSSNIOff, postureContainerEgress, "",
			"--container-egress=enforce requested but could not be applied: " +
				"verifier rejected cg_origin_egress on 6.6.141: 1,000,001 insns",
		},
		{
			ContainerEgressEnforce, TLSSNIEnforce, postureTLSSNI, "mode gate could not be raised: EPERM",
			"--tls-sni=enforce requested but could not be applied: mode gate could not be raised: EPERM",
		},
		{
			ContainerEgressEnforce, TLSSNIEnforcePinned, postureTLSSNI, "mode gate could not be raised: EPERM",
			"--tls-sni=enforce-pinned requested but could not be applied: mode gate could not be raised: EPERM",
		},
	} {
		t.Run("lose "+tc.lose+" under "+tc.egress+"/"+tc.sni, func(t *testing.T) {
			p, buf := ledgerWithLog(t, tc.egress, tc.sni)
			reason := tc.reason
			if reason == "" {
				reason = p.errReason(verifierTooLarge())
			}
			err := p.lose(tc.lose, reason)
			require.EqualError(t, err, tc.want)

			r := p.find(tc.lose)
			assert.True(t, r.degraded(), "a fatal loss still marks the record")
			assert.Equal(t, "off", r.Applied)
			assert.Contains(t, buf.String(), "level=ERROR")
			assert.Contains(t, buf.String(), tc.want[:strings.Index(tc.want, ": ")], "the ledger owns the log line")
		})
	}
}

// Observe is telemetry: losing it warns, records why for the summary, and
// startup carries on. The tls-sni row does not repeat why the hook is down;
// the container-egress row beside it says so.
func TestPostures_LostObserveIsRecordedNotFatal(t *testing.T) {
	redirectStateFiles(t)
	p, buf := ledgerWithLog(t, ContainerEgressObserve, TLSSNIObserve)

	require.NoError(t, p.lose(postureContainerEgress, p.errReason(verifierTooLarge())))
	l7f, err := startL7(&StartCmd{TLSSNI: TLSSNIObserve}, nil, nil, nil, nil, nil, nil, p, p.logger)
	require.NoError(t, err)
	assert.Nil(t, l7f)

	assert.Equal(t, []postureRecord{
		{
			Posture: postureContainerEgress, Requested: "observe", Applied: "off",
			Reason: "verifier rejected cg_origin_egress on 6.6.141: 1,000,001 insns",
		},
		{
			Posture: postureTLSSNI, Requested: "observe", Applied: "off",
			Reason: "the cgroup egress hook it rides is not running",
		},
	}, public(p.records))
	out := buf.String()
	assert.Equal(t, 2, strings.Count(out, "level=WARN"), out)
	assert.NotContains(t, out, "level=ERROR")
	assert.Contains(t, out, `msg="--tls-sni=observe requested but could not be applied"`)

	p.write()
	assert.Equal(t, public(p.records), readPostures(), "the summary must read back exactly what start wrote")
}

// A second loss of the same layer keeps the first reason: it is the cause,
// later reports are its consequences.
func TestPostures_FirstReasonKept(t *testing.T) {
	p, _ := ledgerWithLog(t, ContainerEgressObserve, TLSSNIOff)
	require.NoError(t, p.lose(postureContainerEgress, "first"))
	require.NoError(t, p.lose(postureContainerEgress, "second"))
	assert.Equal(t, "first", p.records[0].Reason)
}

// A layer that was never requested promised nothing, so losing it is not
// an error — even when the other flag's same-spelled rung is fail-closed.
func TestPostures_UnrequestedLayerLossIsNoop(t *testing.T) {
	p, buf := ledgerWithLog(t, ContainerEgressEnforce, TLSSNIOff)
	require.NoError(t, p.lose(postureTLSSNI, "x"))
	assert.Empty(t, buf.String())
}

// Without step attribution the hook never starts: fatal under enforce, a
// recorded warning under observe. The reason carries why.
func TestPostures_ContainerAttributionWithoutStepTracker(t *testing.T) {
	stepErr := errors.New("kernel BTF not found\nsecond line")

	p, _ := ledgerWithLog(t, ContainerEgressEnforce, TLSSNIOff)
	a, err := newContainerAttribution(true, origin.ModeEnforce, nil, stepErr, nil, p, p.logger)
	assert.Nil(t, a)
	assert.EqualError(t, err, "--container-egress=enforce requested but could not be applied: "+
		"step attribution unavailable: kernel BTF not found")

	p, _ = ledgerWithLog(t, ContainerEgressObserve, TLSSNIOff)
	a, err = newContainerAttribution(true, origin.ModeShadow, nil, stepErr, nil, p, p.logger)
	assert.Nil(t, a)
	require.NoError(t, err)
	assert.Equal(t, "step attribution unavailable: kernel BTF not found", p.records[0].Reason)
}

// A hook that fails to load leaves NO attribution, on every rung: a nil
// receiver is the disabled feature, and a live one with no hook would still
// write the loopback infra-allow and start docker tracking with nothing to
// enrich. Under observe the loss is recorded and startup continues; under
// enforce it is fatal. (origin.Start refuses nil TC objects before touching
// the kernel, which stands in for a verifier rejection here.)
func TestPostures_ContainerAttributionHookLoadFailure(t *testing.T) {
	p, _ := ledgerWithLog(t, ContainerEgressObserve, TLSSNIOff)
	a, err := newContainerAttribution(true, origin.ModeShadow, &steps.Tracker{}, nil, nil, p, p.logger)
	require.NoError(t, err)
	assert.Nil(t, a, "a failed load under observe must return the disabled feature")
	assert.True(t, p.records[0].degraded())
	assert.Equal(t, "off", p.records[0].Applied)
	assert.Equal(t, "nil TC BPF objects", p.records[0].Reason)

	p, _ = ledgerWithLog(t, ContainerEgressEnforce, TLSSNIOff)
	a, err = newContainerAttribution(true, origin.ModeEnforce, &steps.Tracker{}, nil, nil, p, p.logger)
	assert.Nil(t, a)
	assert.EqualError(t, err, "--container-egress=enforce requested but could not be applied: nil TC BPF objects")
}

// The file sits in world-writable /tmp and its strings reach markdown: a
// planted newline must not start a new line.
func TestPostures_ReadSanitizes(t *testing.T) {
	redirectStateFiles(t)
	planted, err := json.Marshal([]postureRecord{{
		Posture: "tls-sni", Requested: "observe", Applied: "off",
		Reason: "boom\n::error::injected " + strings.Repeat("x", 1000),
	}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(posturesFile, planted, 0o644))

	got := readPostures()
	require.Len(t, got, 1)
	assert.NotContains(t, got[0].Reason, "\n")
	assert.LessOrEqual(t, len(got[0].Reason), maxPostureReasonBytes+len("..."))

	require.NoError(t, os.WriteFile(posturesFile, []byte("not json"), 0o644))
	assert.Nil(t, readPostures())
}

func TestRenderPostures(t *testing.T) {
	var buf bytes.Buffer
	renderPostures(&buf, nil)
	assert.Empty(t, buf.String(), "nothing requested, nothing rendered")

	renderPostures(&buf, []postureRecord{
		{Posture: postureContainerEgress, Requested: "observe", Applied: "observe"},
	})
	assert.Empty(t, buf.String(), "everything applied: no new noise")

	renderPostures(&buf, []postureRecord{
		{Posture: postureContainerEgress, Requested: "observe", Applied: "off", Reason: "a|b"},
		{Posture: postureTLSSNI, Requested: "observe", Applied: "observe"},
	})
	out := buf.String()
	assert.Contains(t, out, "### Postures not applied")
	assert.Contains(t, out, "| `container-egress` | observe | **off** | a\\|b |")
	assert.NotContains(t, out, "tls-sni", "applied postures stay out of the table")
}

// End to end through Run: the block renders above the dashboard link, so
// the condensed summary cannot hide it.
func TestSummary_Run_LostPostureRenderedAboveLink(t *testing.T) {
	redirectStateFiles(t)
	p, _ := ledgerWithLog(t, ContainerEgressObserve, TLSSNIOff)
	require.NoError(t, p.lose(postureContainerEgress, "verifier rejected cg_origin_egress on 6.6.141: 1,000,001 insns"))
	p.write()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"job_id": "job-1", "workflow_run_url": "https://app.codecargo.io/run/1"}`))
	}))
	t.Cleanup(srv.Close)
	var out bytes.Buffer
	c := &SummaryCmd{
		AuditLog: filepath.Join(t.TempDir(), "never-written.ndjson"),
		Steps:    "[]",
		ApiUrl:   srv.URL,
		Token:    "test-token",
		JobName:  "build",
		Mode:     "enforce",
		output:   &out,
	}
	require.NoError(t, c.Run())

	rendered := out.String()
	block := strings.Index(rendered, "### Postures not applied")
	link := strings.Index(rendered, "[View full details on CodeCargo]")
	require.GreaterOrEqual(t, block, 0, rendered)
	require.GreaterOrEqual(t, link, 0, rendered)
	assert.Less(t, block, link, "postures must render above the link")
	assert.Contains(t, rendered, "1,000,001 insns")
}
