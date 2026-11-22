//go:build linux

package router

import (
	"syscall"
	"testing"

	"github.com/openweir/openwrt/internal/kernel"
)

func TestCoreJailStartsAsRootWithoutSupplementaryGroups(t *testing.T) {
	for _, method := range []string{"tproxy", "tun"} {
		a := coreCommand(method, kernel.Launch{Path: "/core", Config: "/core.yaml"}, "/work").SysProcAttr
		if a == nil || a.Credential == nil || a.Pdeathsig != syscall.SIGTERM || !a.Setpgid {
			t.Fatal(method, a)
		}
		// A non-nil empty list makes setgroups(0) run, so ujail inherits no group.
		if c := a.Credential; c.Uid != 0 || c.Gid != 0 || c.Groups == nil || len(c.Groups) != 0 || c.NoSetGroups {
			t.Fatal(method, c)
		}
		if private := a.Cloneflags == syscall.CLONE_NEWNS; private != (method == "tun") {
			t.Fatal(method, a.Cloneflags)
		}
	}
}
