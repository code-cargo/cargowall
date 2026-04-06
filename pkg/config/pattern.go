package config

import (
	"fmt"
	"strings"
)

// hostnamePattern represents a compiled glob pattern for hostname matching.
// Segments are dot-split elements: literal labels, "*" (one label), or "**" (one or more labels).
type hostnamePattern struct {
	Raw      string
	Segments []string
}

// isHostnamePattern returns true if the value contains glob wildcards.
func isHostnamePattern(value string) bool {
	return strings.Contains(value, "*")
}

// compileHostnamePattern parses a glob pattern string into a hostnamePattern.
// Wildcards: "*" matches one DNS label, "**" matches one or more labels.
func compileHostnamePattern(raw string) (hostnamePattern, error) {
	if raw == "" {
		return hostnamePattern{}, fmt.Errorf("empty pattern")
	}

	segments := strings.Split(raw, ".")
	for i, seg := range segments {
		if seg == "" {
			return hostnamePattern{}, fmt.Errorf("empty segment at position %d in pattern %q", i, raw)
		}
		if seg == "*" || seg == "**" {
			// Reject consecutive ** segments (e.g. "**.**.com") — ambiguous and degenerate
			if seg == "**" && i > 0 && segments[i-1] == "**" {
				return hostnamePattern{}, fmt.Errorf("consecutive ** segments at positions %d-%d in pattern %q", i-1, i, raw)
			}
			continue
		}
		// A segment with a mix of wildcards and literals (e.g. "foo*bar") is not supported
		if strings.Contains(seg, "*") {
			return hostnamePattern{}, fmt.Errorf("partial wildcard %q at position %d not supported (use full * or ** segments)", seg, i)
		}
	}

	return hostnamePattern{Raw: raw, Segments: segments}, nil
}

// Matches returns true if hostname matches the glob pattern.
func (p *hostnamePattern) Matches(hostname string) bool {
	labels := strings.Split(hostname, ".")
	return matchSegments(p.Segments, labels)
}

// matchSegments matches pattern segments against hostname labels using dynamic
// programming to avoid exponential backtracking with multiple "**" segments.
// dp[si][li] reports whether segments[si:] matches labels[li:].
func matchSegments(segments []string, labels []string) bool {
	segCount := len(segments)
	labelCount := len(labels)

	dp := make([][]bool, segCount+1)
	for si := range dp {
		dp[si] = make([]bool, labelCount+1)
	}

	// Both fully consumed — match
	dp[segCount][labelCount] = true

	for si := segCount - 1; si >= 0; si-- {
		seg := segments[si]
		for li := labelCount; li >= 0; li-- {
			switch seg {
			case "**":
				// ** matches one or more labels
				if li < labelCount && (dp[si][li+1] || dp[si+1][li+1]) {
					dp[si][li] = true
				}
			case "*":
				// * matches exactly one label
				if li < labelCount && dp[si+1][li+1] {
					dp[si][li] = true
				}
			default:
				// Literal match
				if li < labelCount && labels[li] == seg && dp[si+1][li+1] {
					dp[si][li] = true
				}
			}
		}
	}

	return dp[0][0]
}
