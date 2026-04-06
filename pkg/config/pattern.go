package config

import (
	"fmt"
	"strings"
)

// HostnamePattern represents a compiled glob pattern for hostname matching.
// Segments are dot-split elements: literal labels, "*" (one label), or "**" (one or more labels).
type HostnamePattern struct {
	Raw      string
	Segments []string
}

// IsHostnamePattern returns true if the hostname value contains glob wildcards.
// Since * is not a valid DNS character, any hostname containing * is a pattern.
func IsHostnamePattern(value string) bool {
	return strings.Contains(value, "*")
}

// CompileHostnamePattern parses a glob pattern string into a HostnamePattern.
func CompileHostnamePattern(raw string) (HostnamePattern, error) {
	if raw == "" {
		return HostnamePattern{}, fmt.Errorf("empty pattern")
	}

	segments := strings.Split(raw, ".")
	for i, seg := range segments {
		if seg == "" {
			return HostnamePattern{}, fmt.Errorf("empty segment at position %d in pattern %q", i, raw)
		}
		if seg == "*" || seg == "**" {
			continue
		}
		// A segment with a mix of wildcards and literals (e.g. "foo*bar") is not supported
		if strings.Contains(seg, "*") {
			return HostnamePattern{}, fmt.Errorf("partial wildcard %q at position %d not supported (use full * or ** segments)", seg, i)
		}
	}

	return HostnamePattern{Raw: raw, Segments: segments}, nil
}

// Matches returns true if hostname matches the glob pattern.
func (p *HostnamePattern) Matches(hostname string) bool {
	labels := strings.Split(hostname, ".")
	return matchSegments(p.Segments, labels)
}

// matchSegments recursively matches pattern segments against hostname labels.
func matchSegments(segments []string, labels []string) bool {
	si, li := 0, 0

	for si < len(segments) {
		seg := segments[si]

		switch seg {
		case "**":
			// ** must match one or more labels
			// Try consuming 1..N remaining labels, then match rest of pattern
			remaining := segments[si+1:]
			for take := 1; take <= len(labels)-li; take++ {
				if matchSegments(remaining, labels[li+take:]) {
					return true
				}
			}
			return false

		case "*":
			// * matches exactly one label
			if li >= len(labels) {
				return false
			}
			si++
			li++

		default:
			// Literal match
			if li >= len(labels) || labels[li] != seg {
				return false
			}
			si++
			li++
		}
	}

	// Both must be fully consumed
	return si == len(segments) && li == len(labels)
}
