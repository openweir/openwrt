//go:build linux

package kernelcli

import (
	"errors"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// execRestricted runs a core check or provider fetch in the running core's identity: root, so
// it reads the root-owned configuration and home, in the core group, whose sockets the
// firewall exempts. Unlike the running core it holds no capability at all: the bounding set
// is emptied and no_new_privs set before execve, which then gives root nothing back.
func execRestricted(args []string) error {
	path, env, e := restrictedArgs(args)
	if e != nil {
		return e
	}
	group, e := user.LookupGroup("openweir-core")
	if e != nil {
		return errors.New("core group unavailable")
	}
	gid, e := strconv.Atoi(group.Gid)
	if e != nil || gid < 1 {
		return errors.New("invalid core GID")
	}
	b, e := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if e != nil {
		return e
	}
	last, e := strconv.Atoi(strings.TrimSpace(string(b)))
	if e != nil || last < 0 || last > 127 {
		return errors.New("invalid capability bound")
	}
	// prctl and capset affect the calling thread, so remain on it through exec.
	runtime.LockOSThread()
	if e = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); e != nil {
		return e
	}
	for i := 0; i <= last; i++ {
		if e = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(i), 0, 0, 0); e != nil {
			return errors.New("cannot drop bounding capability")
		}
	}
	if e = unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); e != nil {
		return e
	}
	if e = syscall.Setgroups([]int{}); e != nil {
		return e
	}
	if e = syscall.Setresgid(gid, gid, gid); e != nil {
		return e
	}
	if e = syscall.Setresuid(0, 0, 0); e != nil {
		return e
	}
	// Empty permitted, effective and inheritable sets: root's execve grants the bounding and
	// inheritable sets, both empty now.
	var none [2]unix.CapUserData
	if e = unix.Capset(&unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}, &none[0]); e != nil {
		return errors.New("cannot clear capabilities")
	}
	if args[1] == "-d" {
		if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0); err != nil {
			return err
		}
		parent, e := strconv.Atoi(os.Getenv("OPENWEIR_PROVIDER_PARENT"))
		if e != nil || os.Getppid() != parent {
			return errors.New("provider refresh ended")
		}
	}
	return syscall.Exec(path, append([]string{path}, args[1:]...), env)
}
