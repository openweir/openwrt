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
)

func prctl(option, arg uintptr) error {
	_, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, option, arg, 0, 0, 0, 0)
	if e != 0 {
		return e
	}
	return nil
}

func execRestricted(args []string) error {
	path, env, e := restrictedArgs(args)
	if e != nil {
		return e
	}
	account, e := user.Lookup("openweir-core")
	if e != nil {
		return errors.New("dedicated core account unavailable")
	}
	uid, e := strconv.Atoi(account.Uid)
	if e != nil || uid < 1 {
		return errors.New("invalid core UID")
	}
	gid, e := strconv.Atoi(account.Gid)
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
	// prctl affects the calling thread, so remain on it through exec.
	runtime.LockOSThread()
	if e = prctl(38, 1); e != nil {
		return e
	} // PR_SET_NO_NEW_PRIVS
	for i := 0; i <= last; i++ {
		if e = prctl(24, uintptr(i)); e != nil {
			return errors.New("cannot drop bounding capability")
		}
	}
	if e = syscall.Setgroups([]int{}); e != nil {
		return e
	}
	if e = syscall.Setresgid(gid, gid, gid); e != nil {
		return e
	}
	if e = syscall.Setresuid(uid, uid, uid); e != nil {
		return e
	}
	if args[1] == "-d" {
		if err := prctl(1, uintptr(syscall.SIGKILL)); err != nil {
			return err
		}
		parent, e := strconv.Atoi(os.Getenv("OPENWEIR_PROVIDER_PARENT"))
		if e != nil || os.Getppid() != parent {
			return errors.New("provider refresh ended")
		}
	}
	return syscall.Exec(path, append([]string{path}, args[1:]...), env)
}
