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

package ebpf

import "testing"

func TestIsKernelSupported(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{"4.19 too old", "4.19.0", false},
		{"5.4 LTS pre-ringbuf", "5.4.0-100-generic", false},
		{"5.7 just below floor", "5.7.0", false},
		{"5.8 exact floor", "5.8.0", true},
		{"5.10 LTS", "5.10.0", true},
		{"5.15 GitLab SaaS aws", "5.15.0-1234-aws", true},
		{"5.15 azure", "5.15.0-1019-azure", true},
		{"6.0", "6.0.0", true},
		{"6.6 tcx era", "6.6.0", true},
		{"6.8 generic", "6.8.0-31-generic", true},
		{"empty", "", false},
		{"garbage", "notakernel", false},
		{"leading v not parseable", "v5.15", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isKernelSupported(tt.version); got != tt.want {
				t.Errorf("isKernelSupported(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
