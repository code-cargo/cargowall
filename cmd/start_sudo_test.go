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
	"io"
	"log/slog"
	"testing"
)

func TestParseSudoAllowCommands(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "single absolute path",
			input: "/usr/bin/kill",
			want:  []string{"/usr/bin/kill"},
		},
		{
			name:  "multiple paths",
			input: "/usr/bin/kill,/usr/sbin/iptables",
			want:  []string{"/usr/bin/kill", "/usr/sbin/iptables"},
		},
		{
			name:  "strips space-separated arguments",
			input: "/usr/bin/kill -9",
			want:  []string{"/usr/bin/kill"},
		},
		{
			name:  "strips tab-separated arguments",
			input: "/usr/bin/kill\t-9",
			want:  []string{"/usr/bin/kill"},
		},
		{
			name:  "strips multiple whitespace arguments",
			input: "/usr/bin/kill  -9  -TERM",
			want:  []string{"/usr/bin/kill"},
		},
		{
			name:  "skips non-absolute path",
			input: "relative/path",
			want:  nil,
		},
		{
			name:  "handles whitespace around commas",
			input: " /usr/bin/kill , /usr/sbin/iptables ",
			want:  []string{"/usr/bin/kill", "/usr/sbin/iptables"},
		},
		{
			name:  "skips empty entries from trailing comma",
			input: "/usr/bin/kill,",
			want:  []string{"/usr/bin/kill"},
		},
		{
			name:  "mixed valid and invalid",
			input: "/usr/bin/kill,relative,/usr/sbin/iptables -t nat",
			want:  []string{"/usr/bin/kill", "/usr/sbin/iptables"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSudoAllowCommands(tt.input, logger)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v (len %d), want %v (len %d)", got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("index %d: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
