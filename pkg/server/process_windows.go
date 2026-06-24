//go:build windows

package server

import (
	"os"
	"syscall"
)

// ProcessAlive reports whether a process with the given PID exists.
func ProcessAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
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
