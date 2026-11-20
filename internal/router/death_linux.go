//go:build linux

package router

import (
	"os/exec"
	"syscall"
)

func processDeath(c *exec.Cmd, privateMounts bool) {
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM, Setpgid: true}
	if privateMounts {
		c.SysProcAttr.Cloneflags = syscall.CLONE_NEWNS
	}
}

func signalCore(c *exec.Cmd, s syscall.Signal) error { return syscall.Kill(-c.Process.Pid, s) }
