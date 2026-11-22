package router

import (
	"encoding/json"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/openweir/openwrt/internal/kernel"
)

func TestCoreJailKeepsRootAndSetsOnlyTheCoreGroup(t *testing.T) {
	launch := kernel.Launch{Path: "/etc/openweir/mihomo-kernel/slots/a/mihomo", Config: "/etc/openweir/mihomo-kernel/configs/c.yaml"}
	work := RunDir + "/core"
	for method, launcher := range map[string]string{"tproxy": "/sbin/ujail", "tun": "/usr/libexec/openweir/tun-jail"} {
		cmd := coreCommand(method, launch, work)
		// No -U: ujail keeps the caller's user, root. -c sets no_new_privs.
		want := []string{launcher, "-G", "openweir-core", "-C", "/etc/openweir/core-capabilities.json", "-c", "-e", "TMPDIR", "-e", "HOME", "--",
			launch.Path, "-d", coreHome, "-f", launch.Config}
		if cmd.Path != launcher || !slices.Equal(cmd.Args, want) {
			t.Fatal(method, cmd.Path, cmd.Args)
		}
		if cmd.Dir != work || !slices.Equal(cmd.Env, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "TMPDIR=" + work, "HOME=" + work}) {
			t.Fatal(method, cmd.Dir, cmd.Env)
		}
	}
}

// ujail clears every set the file leaves out and fails on an unknown name. Root's execve
// grants the bounding and inheritable sets, so each set must be exactly the network pair.
func TestCoreCapabilityFileGrantsOnlyNetworkCapabilities(t *testing.T) {
	b, err := os.ReadFile("../../files" + coreCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	var sets map[string][]string
	if err = json.Unmarshal(b, &sets); err != nil {
		t.Fatal(err)
	}
	names := []string{"ambient", "bounding", "effective", "inheritable", "permitted"}
	if got := slices.Sorted(maps.Keys(sets)); !slices.Equal(got, names) {
		t.Fatal(got)
	}
	for _, name := range names {
		if got := slices.Sorted(slices.Values(sets[name])); !slices.Equal(got, []string{"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE"}) {
			t.Fatal(name, got)
		}
	}
}
