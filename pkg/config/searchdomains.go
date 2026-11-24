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

package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Operator search domains: normalization and validation, shared by every
// loader. The CodeCargo policy loader's per-entry drop is policysearch.go.

// The classes of search domain validateSearchDomain refuses. Each is also
// the short reason a dropped entry is reported with.
var (
	errSearchDomainEmpty        = errors.New("empty")
	errSearchDomainAlwaysActive = errors.New("always active for stripping")
	errSearchDomainSingleLabel  = errors.New("a single label")
	errSearchDomainBadLabel     = errors.New("an invalid label")
	errSearchDomainPublicSuffix = errors.New("a public suffix")
)

// searchDomainError is a refusal with its full message and its class.
type searchDomainError struct {
	class error
	msg   string
}

func (e *searchDomainError) Error() string { return e.msg }

func (e *searchDomainError) Unwrap() error { return e.class }

func searchDomainErr(class error, format string, args ...any) error {
	return &searchDomainError{class: class, msg: fmt.Sprintf(format, args...)}
}

// normalizeSearchDomains lowercases, trims whitespace, ensures a leading dot,
// and deduplicates. Order is preserved by first occurrence.
//
// Empty/whitespace-only entries are PRESERVED (as "") so validateSearchDomains
// can reject them — silently dropping them would let explicit misconfigs like
// `searchDomains: [""]` or `CARGOWALL_SEARCH_DOMAINS=" "` pass unnoticed.
func normalizeSearchDomains(domains []string) []string {
	return dropReverseZoneSearchDomains(normalizeSearchDomainsKeepingReverse(domains))
}

// normalizeSearchDomainsKeepingReverse is normalizeSearchDomains without
// the reverse-zone drop, for the policy loader, which reports those drops
// with its others (filterPolicySearchDomains).
func normalizeSearchDomainsKeepingReverse(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}
	normalized := make([]string, len(domains))
	for i, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && !strings.HasPrefix(d, ".") {
			d = "." + d
		}
		normalized[i] = d
	}
	return mergeNormalizedSearchDomains(nil, normalized)
}

// validateSearchDomain rejects a single normalized suffix that would be too
// broad to safely bypass DNS query filtering.
//
// Three safety nets:
//  1. Multi-label hygiene: must have ≥ 2 labels (rejects ".com"); labels obey
//     RFC 1035 / 1123 (≤ 63 octets, characters [a-z 0-9 -], no leading or
//     trailing hyphen).
//  2. Public Suffix List: must not be a public suffix per Mozilla's PSL.
//     This catches multi-label TLDs like ".co.uk" and ".com.au" that pass
//     the 2-label hygiene but would bypass DNS filtering for huge swaths of
//     the public internet. Private internal suffixes like ".compute.internal"
//     are accepted because they extend beyond the PSL entry (".internal" is
//     on the PSL as a private-use TLD).
//  3. Kubernetes suffixes: the three default K8s search suffixes are
//     always-active for stripping (see kubernetesSearchDomains) but
//     intentionally NOT bypass-eligible. Adding them as a user search
//     domain would silently elevate them to bypass and let K8s service
//     names skip per-hostname DNS filtering. A local config file or the
//     environment fails on one, so the operator decides explicitly; a
//     CodeCargo policy drops it, since it changes nothing there
//     (filterPolicySearchDomains).
//
// Each error carries its class (errors.Is against the errSearchDomain*
// sentinels), so a caller can tell an always-active suffix from a
// misconfiguration and report a short reason.
func validateSearchDomain(d string) error {
	if d == "" || d == "." {
		return searchDomainErr(errSearchDomainEmpty, "search domain must not be empty")
	}
	if slices.Contains(kubernetesSearchDomains, d) {
		return searchDomainErr(errSearchDomainAlwaysActive, "search domain %q is always active for stripping; do not add it to user search domains (would inadvertently grant DNS-filter bypass for all K8s service names)", d)
	}
	bare := strings.TrimPrefix(d, ".")
	labels := strings.Split(bare, ".")
	if len(labels) < 2 {
		return searchDomainErr(errSearchDomainSingleLabel, "search domain %q must have at least two labels (e.g. \".compute.internal\")", d)
	}
	for _, label := range labels {
		if label == "" {
			return searchDomainErr(errSearchDomainBadLabel, "search domain %q has an empty label", d)
		}
		if len(label) > 63 {
			return searchDomainErr(errSearchDomainBadLabel, "search domain %q has label %q longer than 63 octets", d, label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return searchDomainErr(errSearchDomainBadLabel, "search domain %q label %q must not start or end with '-'", d, label)
		}
		for _, r := range label {
			if !(r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z')) {
				return searchDomainErr(errSearchDomainBadLabel, "search domain %q contains invalid character %q", d, r)
			}
		}
	}
	// publicsuffix.PublicSuffix returns the longest known public suffix
	// for the input. If the user's suffix IS that public suffix, they're
	// trying to use a TLD-equivalent as a bypass — reject.
	if eTLD, _ := publicsuffix.PublicSuffix(bare); eTLD == bare {
		return searchDomainErr(errSearchDomainPublicSuffix, "search domain %q is a public suffix (per Mozilla PSL); use a more specific private suffix", d)
	}
	return nil
}

// validateSearchDomains validates a batch of normalized suffixes, returning
// on the first invalid entry. Used by the local config file and env paths,
// where a typo should fail loudly. The CodeCargo policy loader
// (filterPolicySearchDomains) and the in-process auto-allow path use
// validateSearchDomain directly so they can drop per entry.
func validateSearchDomains(domains []string) error {
	for _, d := range domains {
		if err := validateSearchDomain(d); err != nil {
			return err
		}
	}
	return nil
}
