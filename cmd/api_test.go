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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	datapb "github.com/code-cargo/cargowall/pb/cargowall/v1/data"
	"github.com/code-cargo/cargowall/pkg/otlp"
)

// policyEndpoint is the path fetchPolicyFromAPI is expected to call.
const policyEndpoint = "/api/cargowall/v1/action/policy"

// policyServer returns an httptest server that serves the given JSON body for
// the policy endpoint. It asserts the request method, path, job_key/version
// query and bearer token match what fetchPolicyFromAPI is expected to send, so
// the tests also catch endpoint regressions.
func policyServer(t *testing.T, wantJobKey, wantVersion, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, policyEndpoint, r.URL.Path)
		// Assert presence/absence explicitly: fetchPolicyFromAPI must omit an
		// unset param entirely, not send it empty.
		assertQueryParam(t, r, "job_key", wantJobKey)
		assertQueryParam(t, r, "version", wantVersion)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// assertQueryParam asserts that name is absent when want is empty, and carries
// exactly want otherwise.
func assertQueryParam(t *testing.T, r *http.Request, name, want string) {
	t.Helper()
	got, present := r.URL.Query()[name]
	if want == "" {
		assert.False(t, present, "%s must be absent when unset", name)
		return
	}
	assert.Equal(t, []string{want}, got)
}

// TestFetchPolicyFromAPI_IgnoresUnknownField guards against the forward-compat
// bug where a newer controller adding an additive field made the agent reject
// the entire policy (loadCIConfig then warns and falls back to env/file config).
func TestFetchPolicyFromAPI_IgnoresUnknownField(t *testing.T) {
	body := `{
		"mode": "CARGO_WALL_MODE_AUDIT",
		"default_action": "CARGO_WALL_ACTION_TYPE_DENY",
		"future_feature": {"enabled": true, "level": 3},
		"another_unknown": "ignore me"
	}`
	srv := policyServer(t, "job-123", "v1.2.3", body)

	policy, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "job-123", "v1.2.3")
	require.NoError(t, err, "unknown fields must not cause the policy to be dropped")
	require.NotNil(t, policy)
	assert.Equal(t, datapb.CargoWallMode_CARGO_WALL_MODE_AUDIT, policy.Mode)
	assert.Equal(t, datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_DENY, policy.DefaultAction)
}

// TestFetchPolicyFromAPI_IgnoresUnknownEnumValue confirms an enum value name the
// agent doesn't know yet is ignored (field left at its zero value) rather than
// failing the whole parse. Known fields on the same message still parse.
func TestFetchPolicyFromAPI_IgnoresUnknownEnumValue(t *testing.T) {
	body := `{
		"mode": "CARGO_WALL_MODE_FUTURE_VALUE",
		"default_action": "CARGO_WALL_ACTION_TYPE_ALLOW"
	}`
	srv := policyServer(t, "", "", body)

	policy, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "")
	require.NoError(t, err, "unknown enum names must not cause the policy to be dropped")
	require.NotNil(t, policy)
	assert.Equal(t, datapb.CargoWallMode_CARGO_WALL_MODE_UNSPECIFIED, policy.Mode)
	assert.Equal(t, datapb.CargoWallActionType_CARGO_WALL_ACTION_TYPE_ALLOW, policy.DefaultAction)
}

// TestFetchPolicyFromAPI_ReportsVersionWithoutJobKey covers the mixed case: the
// agent reports its version (#92) on a run with no job key, so version must
// still be sent and job_key must stay absent.
func TestFetchPolicyFromAPI_ReportsVersionWithoutJobKey(t *testing.T) {
	srv := policyServer(t, "", "v1.2.3", `{"mode": "CARGO_WALL_MODE_AUDIT"}`)

	policy, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "v1.2.3")
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, datapb.CargoWallMode_CARGO_WALL_MODE_AUDIT, policy.Mode)
}

// setFastPolicyRetries shrinks the retry schedule so retry-path tests run in
// milliseconds, restoring the production values on cleanup.
func setFastPolicyRetries(t *testing.T) {
	t.Helper()
	oldTimeout, oldBase, oldBudget := policyFetchAttemptTimeout, policyFetchBaseBackoff, policyFetchTotalBudget
	policyFetchAttemptTimeout = 2 * time.Second
	policyFetchBaseBackoff = time.Millisecond
	policyFetchTotalBudget = 5 * time.Second
	t.Cleanup(func() {
		policyFetchAttemptTimeout, policyFetchBaseBackoff, policyFetchTotalBudget = oldTimeout, oldBase, oldBudget
	})
}

// countingServer returns a server driven by handler and an attempt counter,
// so tests can assert which classes are retried and which are terminal.
func countingServer(t *testing.T, handler func(w http.ResponseWriter, attempt int32)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, attempts.Add(1))
	}))
	t.Cleanup(srv.Close)
	return srv, &attempts
}

// TestFetchPolicyFromAPI_ClassifiesStatuses drives every status class the
// SaaS can answer with and asserts the classification, whether it counts as
// a retrieval failure (the only kind --api-failure-mode may act on), and the
// retry behavior: outages (429/5xx) are retried, authoritative answers
// (400/401/403/404) are terminal on the first attempt.
func TestFetchPolicyFromAPI_ClassifiesStatuses(t *testing.T) {
	setFastPolicyRetries(t)

	tests := []struct {
		status        int
		wantClass     PolicyFetchClass
		wantRetrieval bool
		wantAttempts  int32
	}{
		{http.StatusBadRequest, PolicyFetchPrecondition, false, 1},
		{http.StatusUnauthorized, PolicyFetchUnauthorized, false, 1},
		{http.StatusForbidden, PolicyFetchUnauthorized, false, 1},
		{http.StatusNotFound, PolicyFetchNotOnboarded, false, 1},
		{http.StatusTooManyRequests, PolicyFetchServer, true, 3},
		{http.StatusInternalServerError, PolicyFetchServer, true, 3},
		{http.StatusServiceUnavailable, PolicyFetchServer, true, 3},
	}
	for _, tc := range tests {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			srv, attempts := countingServer(t, func(w http.ResponseWriter, _ int32) {
				w.WriteHeader(tc.status)
			})

			_, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "")
			var fe *PolicyFetchError
			require.ErrorAs(t, err, &fe)
			assert.Equal(t, tc.wantClass, fe.Class)
			assert.Equal(t, tc.status, fe.StatusCode)
			assert.Equal(t, tc.wantRetrieval, fe.Class.IsRetrievalFailure())
			assert.Equal(t, tc.wantAttempts, attempts.Load())
		})
	}
}

// TestFetchPolicyFromAPI_TransportErrorClassified: a connection failure (no
// HTTP response at all) is a transport-class retrieval failure with no
// status code.
func TestFetchPolicyFromAPI_TransportErrorClassified(t *testing.T) {
	setFastPolicyRetries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	endpoint := srv.URL
	srv.Close()

	_, err := fetchPolicyFromAPI(context.Background(), endpoint, "test-token", "", "")
	var fe *PolicyFetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, PolicyFetchTransport, fe.Class)
	assert.Zero(t, fe.StatusCode)
	assert.True(t, fe.Class.IsRetrievalFailure())
}

// TestFetchPolicyFromAPI_HangClassifiedTransportWithinBudget: a server that
// accepts and never responds must be killed by the per-attempt deadline,
// classified transport (retryable), and truncated by the total budget — the
// hung fetch is the scenario the retry schedule exists for (a single 30s
// attempt used to consume the action's whole readiness window). With the
// budget at 2× the per-attempt timeout (the production 10s/5s ratio), a full
// hang fits only two attempts: policyFetchAttempts is a ceiling, not a
// guarantee (api.go).
func TestFetchPolicyFromAPI_HangClassifiedTransportWithinBudget(t *testing.T) {
	setFastPolicyRetries(t)
	oldBudget := policyFetchTotalBudget
	policyFetchTotalBudget = 2 * policyFetchAttemptTimeout
	t.Cleanup(func() { policyFetchTotalBudget = oldBudget })

	block := make(chan struct{})
	srv, attempts := countingServer(t, func(http.ResponseWriter, int32) {
		<-block // hold the response open past every deadline
	})
	// Registered after countingServer so it runs first (cleanup is LIFO):
	// srv.Close waits for in-flight handlers, which only return once block
	// closes.
	t.Cleanup(func() { close(block) })

	start := time.Now()
	_, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "")
	elapsed := time.Since(start)

	var fe *PolicyFetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, PolicyFetchTransport, fe.Class)
	assert.Zero(t, fe.StatusCode)
	assert.True(t, fe.Class.IsRetrievalFailure())
	assert.Equal(t, int32(2), attempts.Load(),
		"timeout + backoff + timeout ≈ the budget: no third attempt fits")
	assert.GreaterOrEqual(t, elapsed, 2*policyFetchAttemptTimeout,
		"both attempts must have been killed by a deadline, not failed fast")
	assert.Less(t, elapsed, policyFetchTotalBudget+time.Second,
		"a full hang must be bounded by the total budget, not attempts × timeout")
}

// TestFetchPolicyFromAPI_SlowTrickleBodyClassifiedTransport: the per-attempt
// deadline must cover the body read, not just the response headers —
// otherwise a slowloris-style policy endpoint (200, one byte, then stall)
// would hold startup past the budget. The stalled read is transport (the
// retryable "never got the response" class), NOT malformed — the terminal
// class must stay reserved for bodies the server actually finished sending.
func TestFetchPolicyFromAPI_SlowTrickleBodyClassifiedTransport(t *testing.T) {
	setFastPolicyRetries(t)
	oldBudget := policyFetchTotalBudget
	policyFetchTotalBudget = 2 * policyFetchAttemptTimeout
	t.Cleanup(func() { policyFetchTotalBudget = oldBudget })

	block := make(chan struct{})
	srv, attempts := countingServer(t, func(w http.ResponseWriter, _ int32) {
		_, _ = w.Write([]byte("{"))
		// Flush past the server's buffering so client.Do returns and the
		// deadline is genuinely racing the BODY read, not the headers.
		_ = http.NewResponseController(w).Flush()
		<-block // headers and one byte are on the wire; stall the rest
	})
	// Registered after countingServer so it runs first (cleanup is LIFO):
	// srv.Close waits for in-flight handlers, which only return once block
	// closes.
	t.Cleanup(func() { close(block) })

	start := time.Now()
	_, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "")
	elapsed := time.Since(start)

	var fe *PolicyFetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, PolicyFetchTransport, fe.Class,
		"a stalled body read is transport, not malformed")
	assert.True(t, fe.Class.IsRetrievalFailure())
	assert.Equal(t, int32(2), attempts.Load(),
		"each stalled read burns a full attempt timeout, so the budget truncates identically to a full hang")
	assert.Less(t, elapsed, policyFetchTotalBudget+time.Second)
}

// TestFetchPolicyFromAPI_MalformedBodyNotRetried: an unparsable 200 body is a
// retrieval failure (the policy exists but can't be used) yet retrying is
// pointless — the server answered consistently.
func TestFetchPolicyFromAPI_MalformedBodyNotRetried(t *testing.T) {
	setFastPolicyRetries(t)
	srv, attempts := countingServer(t, func(w http.ResponseWriter, _ int32) {
		_, _ = w.Write([]byte("<html>not a policy</html>"))
	})

	_, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "")
	var fe *PolicyFetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, PolicyFetchMalformed, fe.Class)
	assert.True(t, fe.Class.IsRetrievalFailure())
	assert.Equal(t, int32(1), attempts.Load())
}

// TestFetchPolicyFromAPI_RetriesServerErrorThenSucceeds: a transient outage
// that recovers within the retry budget must yield the policy, not a fallback.
func TestFetchPolicyFromAPI_RetriesServerErrorThenSucceeds(t *testing.T) {
	setFastPolicyRetries(t)
	srv, attempts := countingServer(t, func(w http.ResponseWriter, attempt int32) {
		if attempt <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"mode": "CARGO_WALL_MODE_ENFORCE"}`))
	})

	policy, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "")
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, datapb.CargoWallMode_CARGO_WALL_MODE_ENFORCE, policy.Mode)
	assert.Equal(t, int32(3), attempts.Load())
}

// TestFetchPolicyFromAPI_RetryAfterBeyondBudgetFailsFast: a Retry-After
// longer than the remaining fetch budget must return the error immediately
// instead of sleeping out the budget — the action's readiness window is
// counting down, and the sleep could only reproduce the same error.
func TestFetchPolicyFromAPI_RetryAfterBeyondBudgetFailsFast(t *testing.T) {
	setFastPolicyRetries(t)
	oldBudget := policyFetchTotalBudget
	policyFetchTotalBudget = 500 * time.Millisecond
	t.Cleanup(func() { policyFetchTotalBudget = oldBudget })

	srv, attempts := countingServer(t, func(w http.ResponseWriter, _ int32) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	})

	start := time.Now()
	_, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "")
	elapsed := time.Since(start)

	var fe *PolicyFetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, PolicyFetchServer, fe.Class)
	assert.Equal(t, int32(1), attempts.Load(), "no further attempt fits inside the budget")
	assert.Less(t, elapsed, 2*time.Second, "must not sleep out the Retry-After")
}

// TestFetchPolicyFromAPI_TruncatesHugeErrorBody: a non-OK body is quoted into
// the error, which flows to logs and the failure sentinel — it must be
// bounded, not embedded wholesale.
func TestFetchPolicyFromAPI_TruncatesHugeErrorBody(t *testing.T) {
	setFastPolicyRetries(t)
	huge := strings.Repeat("x", 64*1024)
	srv, _ := countingServer(t, func(w http.ResponseWriter, _ int32) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, huge)
	})

	_, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "(truncated)")
	assert.Less(t, len(err.Error()), maxErrorBodyBytes+256, "error must carry at most the truncated snippet")
}

// TestFetchPolicyFromAPI_RedirectChainCapped: the real API never redirects,
// so a redirect loop (misconfigured api-url, captive portal) must be cut
// short and classified as a transport failure instead of following the
// default 10 hops per attempt.
func TestFetchPolicyFromAPI_RedirectChainCapped(t *testing.T) {
	setFastPolicyRetries(t)
	srv, _ := countingServer(t, func(w http.ResponseWriter, _ int32) {
		w.Header().Set("Location", "/api/cargowall/v1/action/policy")
		w.WriteHeader(http.StatusFound)
	})

	_, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "")
	var fe *PolicyFetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, PolicyFetchTransport, fe.Class)
	assert.Contains(t, err.Error(), "stopped after 3 redirects")
}

// TestParseRetryAfter covers the shared parser the fetch retry loop relies
// on: delta-seconds and future HTTP-date forms are honoured, past dates and
// garbage defer to the computed backoff.
func TestParseRetryAfter(t *testing.T) {
	assert.Equal(t, 2*time.Second, otlp.ParseRetryAfter("2"))
	assert.Equal(t, time.Duration(0), otlp.ParseRetryAfter(""))
	assert.Equal(t, time.Duration(0), otlp.ParseRetryAfter("Wed, 21 Oct 2020 07:28:00 GMT"))
	assert.Equal(t, time.Duration(0), otlp.ParseRetryAfter("-5"))
	assert.Greater(t, otlp.ParseRetryAfter(time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)), 55*time.Minute)
}

// TestFetchPolicyFromAPI_UnenumeratedClientErrors: a 4xx the API contract
// doesn't define is still an ANSWER — something understood the request and
// refused it — so it must not be a retrieval failure. Classifying these as
// server-side would let a misconfigured proxy or WAF (402/405/410/451, or a
// 3xx that outlived the redirect cap) drive a deny-all lockdown or silently
// disable enforcement under --api-failure-mode=audit. 408/429 are the
// exceptions: they explicitly mean "try again".
func TestFetchPolicyFromAPI_UnenumeratedClientErrors(t *testing.T) {
	setFastPolicyRetries(t)

	tests := []struct {
		status        int
		wantClass     PolicyFetchClass
		wantRetrieval bool
		wantAttempts  int32
	}{
		{http.StatusPaymentRequired, PolicyFetchPrecondition, false, 1},
		{http.StatusMethodNotAllowed, PolicyFetchPrecondition, false, 1},
		{http.StatusConflict, PolicyFetchPrecondition, false, 1},
		{http.StatusGone, PolicyFetchPrecondition, false, 1},
		{http.StatusUnprocessableEntity, PolicyFetchPrecondition, false, 1},
		{http.StatusUnavailableForLegalReasons, PolicyFetchPrecondition, false, 1},
		{http.StatusProxyAuthRequired, PolicyFetchPrecondition, false, 1},
		// Explicit retry signals stay retryable retrieval failures.
		{http.StatusRequestTimeout, PolicyFetchServer, true, 3},
		{http.StatusTooManyRequests, PolicyFetchServer, true, 3},
		// A 3xx that survived the redirect cap is not an authoritative
		// client refusal — treat it as a server-side anomaly.
		{http.StatusMovedPermanently, PolicyFetchServer, true, 3},
	}
	for _, tc := range tests {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			srv, attempts := countingServer(t, func(w http.ResponseWriter, _ int32) {
				// No Location header: Go returns the 3xx as-is.
				w.WriteHeader(tc.status)
			})

			_, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "")
			var fe *PolicyFetchError
			require.ErrorAs(t, err, &fe)
			assert.Equal(t, tc.wantClass, fe.Class)
			assert.Equal(t, tc.wantRetrieval, fe.Class.IsRetrievalFailure(),
				"an authoritative refusal must not be able to change posture")
			assert.Equal(t, tc.wantAttempts, attempts.Load())
		})
	}
}

// TestFetchPolicyFromAPI_OversizedResponseIsServerError: an oversized 200
// must be reported as a server-side failure, not silently truncated into a
// parse error — "malformed" is terminal (never retried) and would let a
// healthy API drive a lockdown while blaming a response it never sent.
func TestFetchPolicyFromAPI_OversizedResponseIsServerError(t *testing.T) {
	setFastPolicyRetries(t)
	// Valid JSON prefix, then padding past the cap.
	huge := `{"mode": "CARGO_WALL_MODE_AUDIT", "pad": "` + strings.Repeat("x", maxPolicyResponseBytes) + `"}`
	srv, attempts := countingServer(t, func(w http.ResponseWriter, _ int32) {
		_, _ = io.WriteString(w, huge)
	})

	_, err := fetchPolicyFromAPI(context.Background(), srv.URL, "test-token", "", "")
	var fe *PolicyFetchError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, PolicyFetchServer, fe.Class, "an oversized response is a server-side anomaly, not malformed")
	assert.Contains(t, err.Error(), "exceeds")
	assert.Equal(t, int32(3), attempts.Load(), "server class is retried")
}
