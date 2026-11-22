//go:build linux

package router

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/openweir/openwrt/internal/coregroup"
	"github.com/openweir/openwrt/internal/kernel"
)

func TestCoreKeepsRootInItsGroupAlone(t *testing.T) {
	a := coreCommand(kernel.Launch{Path: "/core", Config: "/core.yaml"}, "/work", 4242).SysProcAttr
	if a == nil || a.Credential == nil || a.Pdeathsig != syscall.SIGTERM || !a.Setpgid || a.Setsid {
		t.Fatal(a)
	}
	// A non-nil empty list makes setgroups(0) run, so the core inherits no group of the manager.
	if c := a.Credential; c.Uid != 0 || c.Gid != 4242 || c.Groups == nil || len(c.Groups) != 0 || c.NoSetGroups {
		t.Fatal(c)
	}
	// Nothing narrows what root holds: no namespace, root directory or capability list.
	if a.Cloneflags != 0 || a.Unshareflags != 0 || a.Chroot != "" || a.AmbientCaps != nil || a.UidMappings != nil || a.GidMappings != nil {
		t.Fatal(a)
	}
}

// procStatus reads the fields of /proc/<pid>/status that describe a process's privileges.
func procStatus(t *testing.T, b []byte) map[string]string {
	t.Helper()
	fields := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if ok {
			fields[name] = strings.Join(strings.Fields(value), " ")
		}
	}
	return fields
}

// As root, start a shell the way the core is started and read what it holds. The fixture
// scripts/kernel/check-credentials.sh runs this on OpenWrt's own userland.
func TestCoreLaunchHoldsEveryCapability(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only root can start the core as root in another group")
	}
	gid, err := coregroup.GID()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cmd := coreCommand(kernel.Launch{Path: "/bin/sh", Config: "/dev/null"}, dir, gid)
	cmd.Args = []string{"sh", "-c", "exec cat /proc/self/status"}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	child := procStatus(t, out.Bytes())
	self, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	parent := procStatus(t, self)
	g := strconv.Itoa(gid)
	if child["Uid"] != "0 0 0 0" || child["Gid"] != strings.Repeat(g+" ", 3)+g || child["Groups"] != "" {
		t.Fatal(child["Uid"], child["Gid"], child["Groups"])
	}
	// Root's execve fills the permitted and effective sets from the bounding set, which the
	// launch leaves as the manager's; no_new_privs stays as the manager has it (unset on a router).
	bounding := child["CapBnd"]
	if bounding == "" || bounding != parent["CapBnd"] || child["CapPrm"] != bounding || child["CapEff"] != bounding {
		t.Fatal(child["CapBnd"], child["CapPrm"], child["CapEff"], parent["CapBnd"])
	}
	if child["NoNewPrivs"] != parent["NoNewPrivs"] {
		t.Fatal(child["NoNewPrivs"], parent["NoNewPrivs"])
	}
	if os.Getenv("OPENWEIR_CORE_FIXTURE") == "1" && child["NoNewPrivs"] != "0" {
		t.Fatal("no_new_privs set", child["NoNewPrivs"])
	}
}
