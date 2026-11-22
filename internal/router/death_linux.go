//go:build linux

package router

import (
	"os/exec"
	"syscall"
)

// coreProcess ends the core with its manager and starts its jail as root with no
// supplementary groups, so the core holds only root's user ID and the core group. TUN mode
// gets a private mount namespace for tun-jail's device node.
func coreProcess(c *exec.Cmd, privateMounts bool) {
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM, Setpgid: true, Credential: &syscall.Credential{Groups: []uint32{}}}
	if privateMounts {
		c.SysProcAttr.Cloneflags = syscall.CLONE_NEWNS
	}
}

func signalCore(c *exec.Cmd, s syscall.Signal) error { return syscall.Kill(-c.Process.Pid, s) }
