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
	"fmt"
	"io"
	rand "math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	cargowallv1pb "github.com/code-cargo/cargowall/pb/cargowall/v1"
	"github.com/code-cargo/cargowall/pkg/otlp"
)

// PolicyFetchClass classifies why a policy fetch failed. The distinction is
// load-bearing for --api-failure-mode: --api-url defaults to the SaaS and is
// attempted on every run, so a 404 from an org/repo that isn't onboarded to
// CodeCargo must stay distinguishable from a real outage — otherwise "any
// error → audit/fail" would change posture for every user without a
// CodeCargo account.
type PolicyFetchClass int

const (
	PolicyFetchTransport    PolicyFetchClass = iota // client.Do, deadline, body read
	PolicyFetchServer                               // 5xx, 429
	PolicyFetchMalformed                            // protojson unmarshal, LoadConfigFromCargoWall
	PolicyFetchNotOnboarded                         // 404: org/repo not in CodeCargo
	PolicyFetchUnauthorized                         // 401, 403: token misconfiguration
	PolicyFetchPrecondition                         // 400: e.g. inactive repository
)

func (c PolicyFetchClass) String() string {
	switch c {
	case PolicyFetchTransport:
		return "transport"
	case PolicyFetchServer:
		return "server"
	case PolicyFetchMalformed:
		return "malformed"
	case PolicyFetchNotOnboarded:
		return "not_onboarded"
	case PolicyFetchUnauthorized:
		return "unauthorized"
	case PolicyFetchPrecondition:
		return "precondition"
	}
	return fmt.Sprintf("unknown(%d)", int(c))
}

// IsRetrievalFailure reports whether the class represents a genuine failure
// to retrieve an existing policy (outage or malformed response) — the only
// classes --api-failure-mode may act on. The API answering authoritatively
// that there is nothing to retrieve (not onboarded) or that the client is
// misconfigured (unauthorized, precondition) is not a retrieval failure. An
// onboarded org with no policy assigned returns 200 with a resolved deny-all
// policy, so "onboarded" and "reachable" are cleanly separable on the wire.
func (c PolicyFetchClass) IsRetrievalFailure() bool {
	switch c {
	case PolicyFetchTransport, PolicyFetchServer, PolicyFetchMalformed:
		return true
	}
	return false
}

// retryable reports whether another fetch attempt could plausibly succeed.
// Malformed is a retrieval failure but not retryable: the server answered
// consistently, it just sent something we can't parse.
func (c PolicyFetchClass) retryable() bool {
	return c.IsRetrievalFailure() && c != PolicyFetchMalformed
}

// PolicyFetchError is the classified error returned by fetchPolicyFromAPI.
type PolicyFetchError struct {
	Class      PolicyFetchClass
	StatusCode int // 0 when no HTTP response was received
	err        error

	// retryAfter carries a parsed Retry-After header from a 429 response so
	// the retry loop can honour it over its computed backoff.
	retryAfter time.Duration
}

func (e *PolicyFetchError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("policy fetch failed (class=%s, status=%d): %v", e.Class, e.StatusCode, e.err)
	}
	return fmt.Sprintf("policy fetch failed (class=%s): %v", e.Class, e.err)
}

func (e *PolicyFetchError) Unwrap() error { return e.err }

// classifyStatus maps a non-200 status to a fetch class. The API contract
// returns 400/401/403/404 intentionally; those are answers, not outages.
//
// Every OTHER 4xx is also an answer — the request reached something that
// understood and refused it (a proxy, WAF, or load balancer speaking 402,
// 405, 410, 451, …). Classifying those as `server` would make them
// retrieval failures, so a misconfigured intermediary could drive a
// deny-all lockdown or silently disable enforcement under `audit` — the
// exact "authoritative refusal must not change posture" rule the 404 carve-
// out exists for. They fall back to env/file config with a loud log
// instead, mapped to `precondition` (a client-side configuration state).
//
// The two exceptions are 408 and 429, which explicitly mean "try again":
// they stay `server` so the retry loop and the failure-mode knob treat them
// as the transient conditions they are. 5xx and anything else unexpected
// (including a 3xx that survived the redirect cap) stay `server` too.
func classifyStatus(code int) PolicyFetchClass {
	switch code {
	case http.StatusBadRequest:
		return PolicyFetchPrecondition
	case http.StatusUnauthorized, http.StatusForbidden:
		return PolicyFetchUnauthorized
	case http.StatusNotFound:
		return PolicyFetchNotOnboarded
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return PolicyFetchServer
	}
	if code >= 400 && code < 500 {
		return PolicyFetchPrecondition
	}
	return PolicyFetchServer
}

// Retry schedule for fetchPolicyFromAPI. The action's readiness wait is 30s,
// so the whole fetch (attempts + backoff) must finish comfortably inside it —
// with the old single 30s attempt, a hung fetch timed the action out and the
// fallback posture was unreachable in exactly the case it exists for. Vars so
// tests can shrink the delays.
//
// policyFetchAttempts is a ceiling, not a guarantee: the total budget wins,
// so under a full per-attempt hang only two attempts issue (5s + backoff +
// 5s ≈ the budget). All three run in the common case retries exist for —
// fast transient failures (5xx, connection refused).
var (
	policyFetchAttempts       = 3
	policyFetchAttemptTimeout = 5 * time.Second
	policyFetchBaseBackoff    = 500 * time.Millisecond
	policyFetchTotalBudget    = 10 * time.Second
)

// fetchPolicyFromAPI fetches the resolved CargoWall policy from the CodeCargo
// SaaS API. The endpoint returns the merged policy (org defaults + repo
// overrides + job-level overrides) as a CargoWallPolicy protobuf message
// serialised as JSON. Transient failures (transport errors, 429, 5xx) are
// retried with exponential backoff; all other failures are terminal. On
// failure the returned error is always a *PolicyFetchError.
func fetchPolicyFromAPI(ctx context.Context, apiUrl, token, jobKey, version string) (*cargowallv1pb.CargoWallPolicy, error) {
	endpoint := strings.TrimRight(apiUrl, "/") + "/api/cargowall/v1/action/policy"
	// Empty params are omitted entirely rather than sent blank, so the server
	// can distinguish "not reported" from "reported as empty".
	q := url.Values{}
	if jobKey != "" {
		q.Set("job_key", jobKey)
	}
	if version != "" {
		q.Set("version", version)
	}
	if len(q) > 0 {
		endpoint += "?" + q.Encode()
	}

	ctx, cancel := context.WithTimeout(ctx, policyFetchTotalBudget)
	defer cancel()

	client := &http.Client{
		// The real API never redirects; a misconfigured api-url bouncing
		// through a redirect chain (proxies, captive portals) would burn
		// per-attempt budget, so cap the chain short instead of following
		// the default 10 hops.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("stopped after 3 redirects")
			}
			return nil
		},
	}
	var lastErr *PolicyFetchError
	for attempt := range policyFetchAttempts {
		if attempt > 0 {
			if err := sleepBackoff(ctx, attempt, lastErr.retryAfter); err != nil {
				return nil, lastErr
			}
		}
		policy, ferr := fetchPolicyOnce(ctx, client, endpoint, token)
		if ferr == nil {
			return policy, nil
		}
		lastErr = ferr
		if !ferr.Class.retryable() {
			return nil, ferr
		}
	}
	return nil, lastErr
}

// fetchPolicyOnce performs a single policy fetch attempt with a per-attempt
// timeout, classifying any failure.
func fetchPolicyOnce(ctx context.Context, client *http.Client, endpoint, token string) (*cargowallv1pb.CargoWallPolicy, *PolicyFetchError) {
	ctx, cancel := context.WithTimeout(ctx, policyFetchAttemptTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, &PolicyFetchError{Class: PolicyFetchTransport, err: fmt.Errorf("failed to create HTTP request: %w", err)}
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, &PolicyFetchError{Class: PolicyFetchTransport, err: fmt.Errorf("failed to fetch policy from API: %w", err)}
	}
	defer resp.Body.Close()

	// Bound the read: api-url is env-configurable, so a misconfigured
	// endpoint or interposed proxy could feed an arbitrarily large body.
	// Read one byte past the cap so hitting it is detectable — a silently
	// truncated policy would parse as "malformed" and drive a posture
	// change while blaming a response the server never sent.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyResponseBytes+1))
	if err != nil {
		return nil, &PolicyFetchError{Class: PolicyFetchTransport, err: fmt.Errorf("failed to read API response body: %w", err)}
	}
	if len(body) > maxPolicyResponseBytes {
		return nil, &PolicyFetchError{
			Class:      PolicyFetchServer,
			StatusCode: resp.StatusCode,
			err:        fmt.Errorf("API response exceeds the %d-byte limit", maxPolicyResponseBytes),
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &PolicyFetchError{
			Class:      classifyStatus(resp.StatusCode),
			StatusCode: resp.StatusCode,
			err:        fmt.Errorf("API returned non-OK status %d: %s", resp.StatusCode, truncateForError(body)),
			retryAfter: otlp.ParseRetryAfter(resp.Header.Get("Retry-After")),
		}
	}

	var policy cargowallv1pb.CargoWallPolicy
	// DiscardUnknown so additive fields/enum values from a newer controller
	// don't make us drop the entire policy and fall back to local config.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &policy); err != nil {
		return nil, &PolicyFetchError{Class: PolicyFetchMalformed, err: fmt.Errorf("failed to unmarshal policy response: %w", err)}
	}

	return &policy, nil
}

// sleepBackoff waits before retry number `attempt` (1-based): exponential
// backoff with equal jitter (uniform in [delay, 2·delay), so retries never
// stampede at zero), or the server's Retry-After when it's longer.
// Returns the context error if the total budget expires first, or
// immediately when the delay itself would outlive the budget — sleeping out
// the rest of the budget only to return the same error wastes startup time
// the action's readiness window is counting down.
func sleepBackoff(ctx context.Context, attempt int, retryAfter time.Duration) error {
	delay := policyFetchBaseBackoff << (attempt - 1)
	if delay > 0 {
		delay += rand.N(delay)
	}
	if retryAfter > delay {
		delay = retryAfter
	}
	if deadline, ok := ctx.Deadline(); ok && delay >= time.Until(deadline) {
		return context.DeadlineExceeded
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

// maxPolicyResponseBytes bounds how much of an API response is read (matches
// the OTLP exporter's response cap); maxErrorBodyBytes bounds how much of a
// non-OK body is quoted into the error, which flows to logs and — under
// --api-failure-mode=fail — the failure sentinel the action prints.
const (
	maxPolicyResponseBytes = 1 << 20
	maxErrorBodyBytes      = 1 << 10
)

// truncateForError renders a response body for inclusion in an error
// message. The content is attacker-influenced (api-url is env-configurable),
// and the error flows into the failure sentinel and from there verbatim into
// CI logs — so beyond bounding the length, control characters are stripped:
// without newlines the body can never start a log line, which is what a
// `::`-prefixed GitHub Actions workflow-command injection would need. The
// truncation point is repaired to valid UTF-8 so no mangled rune leaks out.
func truncateForError(body []byte) string {
	truncated := false
	if len(body) > maxErrorBodyBytes {
		body = body[:maxErrorBodyBytes]
		truncated = true
	}
	s := strings.ToValidUTF8(string(body), "�")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if truncated {
		s += "... (truncated)"
	}
	return s
}
