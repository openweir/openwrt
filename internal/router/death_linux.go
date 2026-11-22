//go:build linux

package router

import (
	"os/exec"
	"syscall"
)

// coreProcess ends the core with its manager (the parent-death signal) and starts it in a
// process group of its own, which signalCore stops as a whole. The core keeps root's user ID,
// and with it every capability; gid becomes its real, effective, saved and file-system group,
// which new sockets carry. A non-nil empty list runs setgroups(0), so it holds no other group.
func coreProcess(c *exec.Cmd, gid int) {
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM, Setpgid: true,
		Credential: &syscall.Credential{Uid: 0, Gid: uint32(gid), Groups: []uint32{}}}
}

func signalCore(c *exec.Cmd, s syscall.Signal) error { return syscall.Kill(-c.Process.Pid, s) }
