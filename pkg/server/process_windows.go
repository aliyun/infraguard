//go:build windows

package server

import (
	"os"
	"syscall"
)

// ProcessAlive reports whether a process with the given PID exists.
func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	const processQueryLimitedInformation = 0x1000
	const stillActive = 259
	handle, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(handle)
	var exitCode uint32
	return syscall.GetExitCodeProcess(handle, &exitCode) == nil && exitCode == stillActive
}

// DetachAttr returns SysProcAttr that detaches the child process.
func DetachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}

// TerminatePID terminates a PID.
func TerminatePID(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
