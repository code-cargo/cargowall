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
	"fmt"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Operator search domains: normalization and classification, shared by
// every loader. The CodeCargo policy loader's per-entry drop is
// policysearch.go.

// searchDomainClass is what classifySearchDomain makes of an entry: usable,
// or the reason it is not. Its String is the short reason a dropped entry
// is reported with.
type searchDomainClass uint8

const (
	searchDomainOK searchDomainClass = iota
	searchDomainEmpty
	searchDomainReverseZone
	searchDomainAlwaysActive
	searchDomainSingleLabel
	searchDomainEmptyLabel
	searchDomainLongLabel
	searchDomainHyphenLabel
	searchDomainBadCharacter
	searchDomainPublicSuffix
)

func (c searchDomainClass) String() string {
	switch c {
	case searchDomainOK:
		return "usable"
	case searchDomainEmpty:
		return "empty"
	case searchDomainReverseZone:
		return "under a reverse-lookup zone, which no search domain decides"
	case searchDomainAlwaysActive:
		return "always active for stripping"
	case searchDomainSingleLabel:
		return "a single label"
	case searchDomainEmptyLabel:
		return "an empty label"
	case searchDomainLongLabel:
		return "a label longer than 63 octets"
	case searchDomainHyphenLabel:
		return "a label that starts or ends with a hyphen"
	case searchDomainBadCharacter:
		return "a character outside a-z, 0-9 and hyphen"
	case searchDomainPublicSuffix:
		return "a public suffix"
	default:
		return "refused"
	}
}

// normalizeSearchDomain is THE normalization of one entry: lowercased,
// trimmed of whitespace and of a trailing dot (a suffix written as an
// FQDN), with a leading dot. An entry of only whitespace or dots stays "",
// which classifies as empty: dropping it silently would let explicit
// misconfigs like `searchDomains: [""]` or `CARGOWALL_SEARCH_DOMAINS=" "`
// pass unnoticed.
func normalizeSearchDomain(raw string) string {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if d != "" && !strings.HasPrefix(d, ".") {
		d = "." + d
	}
	if d == "." {
		return ""
	}
	return d
}

// normalizeSearchDomains normalizes each entry, deduplicates (order by
// first occurrence), and drops those under a reverse-lookup zone with a
// warning each (dropReverseZoneSearchDomains). Used by the local config
// file and env loaders, which then validate the rest.
func normalizeSearchDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}
	normalized := make([]string, len(domains))
	for i, d := range domains {
		normalized[i] = normalizeSearchDomain(d)
	}
	return dropReverseZoneSearchDomains(mergeNormalizedSearchDomains(nil, normalized))
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
// classifySearchDomain gives the class of a refusal too, so a caller can
// tell an always-active suffix from a misconfiguration and report a short
// reason.
func validateSearchDomain(d string) error {
	_, err := classifySearchDomain(d)
	return err
}

// classifySearchDomain is validateSearchDomain with the class of what it
// found. An entry under a reverse-lookup zone is classed apart before any
// other test: every loader drops it with a warning rather than failing on
// it, since it could never take effect.
func classifySearchDomain(d string) (searchDomainClass, error) {
	if d == "" || d == "." {
		return searchDomainEmpty, fmt.Errorf("search domain must not be empty")
	}
	if ReverseLookupName(d) {
		return searchDomainReverseZone, fmt.Errorf("search domain %q is under a reverse-lookup zone, which no search domain decides", d)
	}
	if slices.Contains(kubernetesSearchDomains, d) {
		return searchDomainAlwaysActive, fmt.Errorf("search domain %q is always active for stripping; do not add it to user search domains (would inadvertently grant DNS-filter bypass for all K8s service names)", d)
	}
	bare := strings.TrimPrefix(d, ".")
	labels := strings.Split(bare, ".")
	if len(labels) < 2 {
		return searchDomainSingleLabel, fmt.Errorf("search domain %q must have at least two labels (e.g. \".compute.internal\")", d)
	}
	for _, label := range labels {
		if label == "" {
			return searchDomainEmptyLabel, fmt.Errorf("search domain %q has an empty label", d)
		}
		if len(label) > 63 {
			return searchDomainLongLabel, fmt.Errorf("search domain %q has label %q longer than 63 octets", d, label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return searchDomainHyphenLabel, fmt.Errorf("search domain %q label %q must not start or end with '-'", d, label)
		}
		for _, r := range label {
			if !(r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z')) {
				return searchDomainBadCharacter, fmt.Errorf("search domain %q contains invalid character %q", d, r)
			}
		}
	}
	// publicsuffix.PublicSuffix returns the longest known public suffix
	// for the input. If the user's suffix IS that public suffix, they're
	// trying to use a TLD-equivalent as a bypass — reject.
	if eTLD, _ := publicsuffix.PublicSuffix(bare); eTLD == bare {
		return searchDomainPublicSuffix, fmt.Errorf("search domain %q is a public suffix (per Mozilla PSL); use a more specific private suffix", d)
	}
	return searchDomainOK, nil
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
