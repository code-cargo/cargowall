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

package lockdown

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ubuntuSudoers is the shape Debian and Ubuntu ship: the includedir last.
const ubuntuSudoers = `Defaults	env_reset
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root	ALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
%sudo	ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "@include" directives:

@includedir /etc/sudoers.d
`

// arcSudoers is the actions-runner image's whole /etc/sudoers: a group
// grant and no include.
const arcSudoers = "%sudo   ALL=(ALL:ALL) NOPASSWD:ALL\n"

const testRules = "runner ALL=(ALL:ALL) !ALL\nrunner ALL=(ALL) NOPASSWD: /usr/sbin/iptables\n"

func TestReadsLockdownLast(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"ubuntu default", ubuntuSudoers, true},
		{"hash spelling", "%sudo ALL=(ALL) ALL\n#includedir /etc/sudoers.d\n", true},
		{"comments and blanks after", "%sudo ALL=(ALL) ALL\n@includedir /etc/sudoers.d\n\n# trailing note\n   \n", true},
		{"quoted with a trailing slash", "@includedir \"/etc/sudoers.d/\"\n", true},
		{"no trailing newline", "@includedir /etc/sudoers.d", true},
		{"arc image: group grant, no include", arcSudoers, false},
		{"grant after the include", "@includedir /etc/sudoers.d\n%sudo ALL=(ALL:ALL) NOPASSWD:ALL\n", false},
		{"defaults after the include", "@includedir /etc/sudoers.d\nDefaults !lecture\n", false},
		{"commented-out include", "%sudo ALL=(ALL) ALL\n# includedir /etc/sudoers.d\n", false},
		{"another directory", "@includedir /etc/sudoers.local\n", false},
		{"one file of the directory", "@include /etc/sudoers.d/runner\n", false},
		{"keyword alone", "%sudo ALL=(ALL) ALL\n#includedir\n", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := readsLockdownLast(tt.content, "/etc/sudoers.d"); got != tt.want {
				t.Errorf("readsLockdownLast = %v, want %v\n%s", got, tt.want, tt.content)
			}
		})
	}
}

func TestWithoutBlock(t *testing.T) {
	block := lockdownBlock(testRules)
	tests := []struct {
		name    string
		content string
		want    string
		found   bool
		wantErr bool
	}{
		{name: "no block", content: arcSudoers, want: arcSudoers},
		{name: "block at the end", content: arcSudoers + block, want: arcSudoers, found: true},
		{name: "block between lines", content: "a\n" + block + "b\n", want: "a\nb\n", found: true},
		{name: "begin without end", content: arcSudoers + blockBegin + "\n" + testRules, wantErr: true},
		{name: "end without begin", content: arcSudoers + blockEnd + "\n", wantErr: true},
		{name: "second begin", content: blockBegin + "\n" + block, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found, err := withoutBlock(tt.content)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want || found != tt.found {
				t.Errorf("withoutBlock = %q, %v; want %q, %v", got, found, tt.want, tt.found)
			}
		})
	}
}

func TestWithBlock(t *testing.T) {
	got, err := withBlock("%sudo ALL=(ALL) ALL", testRules)
	if err != nil {
		t.Fatal(err)
	}
	if want := "%sudo ALL=(ALL) ALL\n" + lockdownBlock(testRules); got != want {
		t.Errorf("a file without a trailing newline: got %q, want %q", got, want)
	}

	again, err := withBlock(got, testRules)
	if err != nil {
		t.Fatal(err)
	}
	if again != got {
		t.Errorf("not idempotent:\n%q\n%q", got, again)
	}

	other := "runner ALL=(ALL:ALL) !ALL\n"
	replaced, err := withBlock(got, other)
	if err != nil {
		t.Fatal(err)
	}
	if want := "%sudo ALL=(ALL) ALL\n" + lockdownBlock(other); replaced != want {
		t.Errorf("a previous block is not replaced: got %q, want %q", replaced, want)
	}
}

// stubVisudo stands in for visudo for the test, returning err and counting
// calls.
func stubVisudo(t *testing.T, err error) *int {
	t.Helper()
	calls := 0
	prev := visudoCheckFile
	visudoCheckFile = func(string) error {
		calls++
		return err
	}
	t.Cleanup(func() { visudoCheckFile = prev })
	return &calls
}

func writeSudoers(t *testing.T, content string) string {
	t.Helper()
	main := filepath.Join(t.TempDir(), "sudoers")
	if err := os.WriteFile(main, []byte(content), 0o440); err != nil {
		t.Fatal(err)
	}
	return main
}

func readString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestAppendSudoersBlock_arcShape(t *testing.T) {
	calls := stubVisudo(t, nil)
	main := writeSudoers(t, arcSudoers)

	appended, err := appendSudoersBlock(main, "/etc/sudoers.d", testRules)
	if err != nil {
		t.Fatal(err)
	}
	if !appended {
		t.Fatal("a sudoers without the include gets no block")
	}
	if got, want := readString(t, main), arcSudoers+lockdownBlock(testRules); got != want {
		t.Errorf("content: got %q, want %q", got, want)
	}
	if fi, err := os.Stat(main); err != nil || fi.Mode().Perm() != 0o440 {
		t.Errorf("mode not kept: %v %v", fi.Mode(), err)
	}
	if *calls != 1 {
		t.Errorf("visudo calls = %d, want 1", *calls)
	}

	removed, err := removeSudoersBlock(main)
	if err != nil || !removed {
		t.Fatalf("removeSudoersBlock = %v, %v", removed, err)
	}
	if got := readString(t, main); got != arcSudoers {
		t.Errorf("not restored byte for byte: got %q", got)
	}
	removed, err = removeSudoersBlock(main)
	if err != nil || removed {
		t.Errorf("a second removal = %v, %v; want false, nil", removed, err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(main)); len(entries) != 1 {
		t.Errorf("left files behind: %v", entries)
	}
}

func TestAppendSudoersBlock_readsLastAlready(t *testing.T) {
	calls := stubVisudo(t, nil)
	main := writeSudoers(t, ubuntuSudoers)

	appended, err := appendSudoersBlock(main, "/etc/sudoers.d", testRules)
	if err != nil || appended {
		t.Fatalf("appendSudoersBlock = %v, %v; want false, nil", appended, err)
	}
	if got := readString(t, main); got != ubuntuSudoers {
		t.Errorf("a sudoers that reads the lockdown last was changed: %q", got)
	}
	if *calls != 0 {
		t.Errorf("visudo calls = %d, want 0", *calls)
	}
}

func TestAppendSudoersBlock_removesStaleBlockWhereNoneIsNeeded(t *testing.T) {
	stubVisudo(t, nil)
	// A block a crashed run left above the include, which sudo reads last.
	main := writeSudoers(t, lockdownBlock("runner ALL=(ALL) NOPASSWD: /bin/old\n")+ubuntuSudoers)

	appended, err := appendSudoersBlock(main, "/etc/sudoers.d", testRules)
	if err != nil || appended {
		t.Fatalf("appendSudoersBlock = %v, %v; want false, nil", appended, err)
	}
	if got := readString(t, main); got != ubuntuSudoers {
		t.Errorf("stale block not removed: %q", got)
	}
}

func TestAppendSudoersBlock_visudoRejects(t *testing.T) {
	stubVisudo(t, errors.New("syntax error"))
	main := writeSudoers(t, arcSudoers)

	if _, err := appendSudoersBlock(main, "/etc/sudoers.d", testRules); err == nil {
		t.Fatal("expected an error")
	}
	if got := readString(t, main); got != arcSudoers {
		t.Errorf("a rejected edit reached the file: %q", got)
	}
	if entries, _ := os.ReadDir(filepath.Dir(main)); len(entries) != 1 {
		t.Errorf("left files behind: %v", entries)
	}
}

func TestAppendSudoersBlock_missingFile(t *testing.T) {
	calls := stubVisudo(t, nil)
	main := filepath.Join(t.TempDir(), "sudoers")
	appended, err := appendSudoersBlock(main, "/etc/sudoers.d", testRules)
	if err != nil || appended {
		t.Fatalf("appendSudoersBlock = %v, %v; want false, nil", appended, err)
	}
	if removed, err := removeSudoersBlock(main); err != nil || removed {
		t.Errorf("removeSudoersBlock = %v, %v; want false, nil", removed, err)
	}
	if *calls != 0 {
		t.Errorf("visudo calls = %d, want 0", *calls)
	}
}

func TestAppendSudoersBlock_brokenMarkers(t *testing.T) {
	stubVisudo(t, nil)
	broken := arcSudoers + blockBegin + "\n" + testRules
	main := writeSudoers(t, broken)
	if _, err := appendSudoersBlock(main, "/etc/sudoers.d", testRules); err == nil {
		t.Error("appendSudoersBlock: expected an error for a block without its end")
	}
	if _, err := removeSudoersBlock(main); err == nil {
		t.Error("removeSudoersBlock: expected an error for a block without its end")
	}
	if got := readString(t, main); got != broken {
		t.Errorf("a file with broken markers was changed: %q", got)
	}
}

func TestReplaceSudoers_refusesSymlink(t *testing.T) {
	stubVisudo(t, nil)
	target := writeSudoers(t, arcSudoers)
	link := filepath.Join(t.TempDir(), "sudoers")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := replaceSudoers(link, "x\n"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("replaceSudoers through a symlink: %v", err)
	}
	if got := readString(t, target); got != arcSudoers {
		t.Errorf("symlink target changed: %q", got)
	}
}
