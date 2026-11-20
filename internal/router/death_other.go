//go:build !linux

package router

import (
	"os/exec"
	"syscall"
)

func processDeath(c *exec.Cmd, privateMounts bool) {}

func signalCore(c *exec.Cmd, s syscall.Signal) error { return c.Process.Signal(s) }
