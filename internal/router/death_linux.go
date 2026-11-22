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

// coreFiles is the core's open-file limit, soft and hard, as OpenClash's procd instance has
// it (limits nofile="1000000 1000000"); the init script asks procd for the same. Every
// proxied connection holds at least two descriptors, and procd's default is 1024 soft, 4096
// hard.
const coreFiles = 1000000

// setFileLimit makes n the manager's open-file limit, soft and hard. Go raised its own soft
// limit at startup and puts the original soft limit back in each process it starts, unless
// the program sets the limit itself, as here: from now on the core inherits n, soft and hard.
// When the kernel refuses n (above fs.nr_open, or a hard limit to raise without
// CAP_SYS_RESOURCE), children get the soft limit raised to the hard one, and the error.
func setFileLimit(n uint64) error {
	err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: n, Max: n})
	if err != nil {
		var lim syscall.Rlimit
		if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim) == nil {
			lim.Cur = lim.Max
			_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
		}
	}
	return err
}
