//go:build !windows

package server

import "syscall"

// ProcessAlive reports whether a process with the given PID exists.
func ProcessAlive(pid int) bool {
	// Signal 0 performs error checking without sending a signal.
	return syscall.Kill(pid, 0) == nil
}

// DetachAttr returns SysProcAttr that detaches the child into its own session.
func DetachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// TerminatePID sends SIGTERM to a PID.
func TerminatePID(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}
