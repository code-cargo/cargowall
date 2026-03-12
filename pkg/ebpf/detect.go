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

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"
)

// Capabilities represents the eBPF capabilities of the current environment
type Capabilities struct {
	// KernelVersion is the running kernel version string
	KernelVersion string
	// KernelSupported indicates if the kernel version supports eBPF TC programs
	KernelSupported bool
	// BPFSyscall indicates if the BPF syscall is available
	BPFSyscall bool
	// CanCreatePrograms indicates if we can create eBPF programs
	CanCreatePrograms bool
	// HasCAP_BPF indicates if CAP_BPF capability is available
	HasCAP_BPF bool
	// HasCAP_NET_ADMIN indicates if CAP_NET_ADMIN capability is available
	HasCAP_NET_ADMIN bool
	// Error contains any error encountered during detection
	Error error
}

// IsSupported returns true if all required eBPF capabilities are available
func (c *Capabilities) IsSupported() bool {
	return c.KernelSupported && c.BPFSyscall && c.CanCreatePrograms
}

// Summary provides a human-readable summary of capabilities
func (c *Capabilities) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Kernel: %s (supported: %v)\n", c.KernelVersion, c.KernelSupported))
	sb.WriteString(fmt.Sprintf("BPF syscall: %v\n", c.BPFSyscall))
	sb.WriteString(fmt.Sprintf("Can create programs: %v\n", c.CanCreatePrograms))
	sb.WriteString(fmt.Sprintf("CAP_BPF: %v\n", c.HasCAP_BPF))
	sb.WriteString(fmt.Sprintf("CAP_NET_ADMIN: %v\n", c.HasCAP_NET_ADMIN))
	if c.Error != nil {
		sb.WriteString(fmt.Sprintf("Error: %v\n", c.Error))
	}
	return sb.String()
}

// Detect probes the current environment for eBPF capabilities
func Detect() *Capabilities {
	caps := &Capabilities{}

	// Get kernel version
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		caps.Error = fmt.Errorf("failed to get kernel version: %w", err)
		return caps
	}
	caps.KernelVersion = int8ArrayToString(uname.Release[:])

	// Check kernel version (need 5.x+ for TCX, 4.15+ for basic TC)
	caps.KernelSupported = isKernelSupported(caps.KernelVersion)

	// Check capabilities
	caps.HasCAP_BPF = hasCapability(unix.CAP_BPF)
	caps.HasCAP_NET_ADMIN = hasCapability(unix.CAP_NET_ADMIN)

	// Try to use BPF syscall
	caps.BPFSyscall = checkBPFSyscall()

	// Try to create a minimal eBPF program
	caps.CanCreatePrograms = checkCanCreateProgram()

	return caps
}

// isKernelSupported checks if the kernel version supports eBPF TC programs.
// TCX (the modern TC attachment method) requires kernel 6.6+
// TC BPF (legacy) requires kernel 4.15+
// We target 5.x+ as a reasonable minimum for GitHub Actions runners
func isKernelSupported(version string) bool {
	var major, minor int
	_, err := fmt.Sscanf(version, "%d.%d", &major, &minor)
	if err != nil {
		return false
	}

	// Require kernel 5.0 or newer for eBPF TC support
	// GitHub Actions runners typically run Ubuntu 22.04 with kernel 6.x
	if major >= 6 {
		return true
	}
	if major == 5 {
		return true
	}
	return false
}

// hasCapability checks if the current process has the specified capability
func hasCapability(cap int) bool {
	// Use prctl to check effective capabilities
	var capData [2]unix.CapUserData
	capHeader := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0, // 0 means current process
	}

	if err := unix.Capget(&capHeader, &capData[0]); err != nil {
		return false
	}

	// Check if the capability is in the effective set
	capIndex := cap / 32
	capBit := uint32(1) << (cap % 32)

	if capIndex >= len(capData) {
		return false
	}

	return capData[capIndex].Effective&capBit != 0
}

// checkBPFSyscall checks if the BPF syscall is available
func checkBPFSyscall() bool {
	// Try a simple BPF syscall that should fail gracefully if BPF is available
	// BPF_PROG_GET_FD_BY_ID with ID 0 should return ENOENT if BPF works
	_, _, errno := syscall.Syscall(
		unix.SYS_BPF,
		unix.BPF_PROG_GET_FD_BY_ID,
		0,
		0,
	)

	// ENOENT or EINVAL means the syscall works but we asked for invalid data
	// EPERM means we don't have permission
	// ENOSYS means the syscall doesn't exist
	return errno != syscall.ENOSYS
}

// checkCanCreateProgram attempts to create a minimal eBPF program to verify
// that we have the necessary permissions and kernel support
func checkCanCreateProgram() bool {
	// Create a minimal BPF program that just returns 0
	spec := &ebpf.ProgramSpec{
		Type: ebpf.SchedCLS,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "GPL",
	}

	prog, err := ebpf.NewProgram(spec)
	if err != nil {
		return false
	}
	prog.Close()
	return true
}

// int8ArrayToString converts a null-terminated int8 array to a string
func int8ArrayToString(arr []int8) string {
	var buf []byte
	for _, v := range arr {
		if v == 0 {
			break
		}
		buf = append(buf, byte(v))
	}
	return string(buf)
}

// RequireCapabilities checks for eBPF support and returns an error if not available.
// This is intended to be called at startup to provide a clear error message.
func RequireCapabilities() error {
	caps := Detect()

	if caps.IsSupported() {
		return nil
	}

	var reasons []string

	if !caps.KernelSupported {
		reasons = append(reasons, fmt.Sprintf("kernel %s is not supported (need 5.x+)", caps.KernelVersion))
	}

	if !caps.BPFSyscall {
		reasons = append(reasons, "BPF syscall is not available")
	}

	if !caps.CanCreatePrograms {
		reasons = append(reasons, "cannot create eBPF programs (check permissions/capabilities)")
	}

	if !caps.HasCAP_BPF && !caps.HasCAP_NET_ADMIN {
		reasons = append(reasons, "missing CAP_BPF and CAP_NET_ADMIN capabilities")
	}

	// Check if running in unprivileged mode
	if os.Geteuid() != 0 {
		reasons = append(reasons, "not running as root")
	}

	return fmt.Errorf("eBPF not supported: %s", strings.Join(reasons, "; "))
}
