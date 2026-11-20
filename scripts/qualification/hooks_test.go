// Package qualification holds host-side tests of the router shell hooks.
package qualification

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const root = "../.."

// Backend selection must reflect the live kernel rules and the actual xtables ABI.
func inspectFirewall(t *testing.T, nft, xtVersion, xtActive string) string {
	t.Helper()
	tools := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(tools, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("nft", "#!/bin/sh\nif [ \"$1\" = --version ]; then echo \"nftables v1.1.1\"; else test \"$NFT_ACTIVE\" = yes; fi\n")
	write("iptables", "#!/bin/sh\nif [ \"$1\" = -V ]; then echo \"iptables v1.8.10 ($XT_VERSION)\"; "+
		"elif [ \"$XT_ACTIVE\" = yes ]; then echo '-A INPUT -m comment --comment \"!fw3\" -j ACCEPT'; fi\n")
	// The fixture excludes any host firewall executable.
	for _, name := range []string{"awk", "grep"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Skip(name, "unavailable")
		}
		if err := os.Symlink(path, filepath.Join(tools, name)); err != nil {
			t.Fatal(err)
		}
	}
	network, _ := filepath.Abs(filepath.Join(root, "files/usr/libexec/openweir/network"))
	cmd := exec.Command(network, "environment")
	cmd.Env = append(os.Environ(), "PATH="+tools, "NFT_ACTIVE="+nft, "XT_VERSION="+xtVersion, "XT_ACTIVE="+xtActive)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestFirewallSelection(t *testing.T) {
	for _, c := range []struct{ nft, version, active, want string }{
		// xtables-nft is not a second firewall.
		{"yes", "nf_tables", "yes", "fw4 nftables v1.1.1"},
		{"no", "nf_tables", "yes", "unavailable"},
		// Installed but inactive is not a firewall.
		{"no", "legacy", "no", "unavailable"},
		{"yes", "legacy", "no", "fw4 nftables v1.1.1"},
		// Legacy and mixed.
		{"no", "legacy", "yes", "fw3 iptables-legacy v1.8.10"},
		{"yes", "legacy", "yes", "ambiguous"},
	} {
		if got := inspectFirewall(t, c.nft, c.version, c.active); got != c.want {
			t.Errorf("nft=%s xtables=%s/%s: %q, want %q", c.nft, c.version, c.active, got, c.want)
		}
	}
}

// Offline-image and failure recovery coverage for the native package hook.

func elf(tail string, machine ...byte) []byte {
	if machine == nil {
		machine = []byte{0xb7, 0x00}
	}
	b := append([]byte("\x7fELF\x02\x01"), make([]byte, 12)...)
	b = append(b, machine...)
	b = append(b, make([]byte, 44)...)
	return append(b, tail...)
}

func entry(content []byte, name string) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

func gz(t *testing.T, data []byte) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(data)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type activation struct {
	t                      *testing.T
	root, runtime, payload string
	manager                string
	binary                 []byte
	env                    []string
}

func newActivation(t *testing.T) *activation {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("the flock command is unavailable")
	}
	a := &activation{t: t, root: t.TempDir()}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(a.root, "bin"), 0o755))
	must(os.WriteFile(filepath.Join(a.root, "bin/busybox"), elf("fixture"), 0o644))
	a.env = append(os.Environ(), "IPKG_INSTROOT="+a.root)
	a.runtime = filepath.Join(a.root, "usr/libexec/openweir")
	must(os.MkdirAll(a.runtime, 0o755))
	abi, err := os.ReadFile(filepath.Join(root, "packaging/openwrt/runtime-abi"))
	must(err)
	must(os.WriteFile(filepath.Join(a.runtime, "runtime-abi"), abi, 0o755))
	must(os.MkdirAll(filepath.Join(a.root, "etc"), 0o755))
	must(os.WriteFile(filepath.Join(a.root, "etc/openwrt_release"), []byte("DISTRIB_ARCH='aarch64_generic'\n"), 0o644))
	a.payload = filepath.Join(a.root, "tmp/openweir-package-payload")
	must(os.MkdirAll(a.payload, 0o700))
	must(os.Chmod(a.payload, 0o700))
	a.manager = filepath.Join(a.runtime, "manager")
	a.binary = elf("new manager")
	a.stage(a.binary)
	return a
}

func (a *activation) write(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		a.t.Fatal(err)
	}
}

func (a *activation) read(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		a.t.Fatal(err)
	}
	return string(data)
}

func (a *activation) stage(binary []byte) {
	compressed := gz(a.t, binary)
	foreign := gz(a.t, elf("foreign CPU", 0x3e, 0x00))
	a.write(filepath.Join(a.payload, "arm64.gz"), compressed)
	a.write(filepath.Join(a.payload, "amd64.gz"), foreign)
	a.write(filepath.Join(a.payload, "SHA256SUMS"), []byte(entry(compressed, "arm64.gz")+entry(foreign, "amd64.gz")))
	a.write(filepath.Join(a.runtime, "runtime.sha256"), []byte(entry(binary, "arm64")))
}

func (a *activation) activate(success bool) string {
	a.t.Helper()
	script, _ := filepath.Abs(filepath.Join(root, "packaging/openwrt/activate-runtime"))
	cmd := exec.Command("sh", script)
	cmd.Env = a.env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if (err == nil) != success {
		a.t.Fatalf("activate-runtime: %v\n%s", err, stderr.String())
	}
	return stderr.String()
}

func exists(path string) bool { _, err := os.Lstat(path); return err == nil }

func TestOfflineSelectsCPUAndReconfiguresAfterPayloadCleanup(t *testing.T) {
	a := newActivation(t)
	a.activate(true)
	if a.read(a.manager) != string(a.binary) {
		t.Fatal("wrong manager")
	}
	if info, _ := os.Stat(a.manager); info.Mode().Perm() != 0o755 {
		t.Fatal(info.Mode())
	}
	if exists(a.payload) {
		t.Fatal("payload kept")
	}
	a.activate(true)
}

func TestBadArchiveAndWrongCPUPreservePreviousManager(t *testing.T) {
	a := newActivation(t)
	old := elf("old manager")
	a.write(a.manager, old)
	a.write(filepath.Join(a.payload, "arm64.gz"), []byte("incomplete"))
	if !strings.Contains(a.activate(false), "archive checksum mismatch") || a.read(a.manager) != string(old) {
		t.Fatal("bad archive accepted")
	}
	a.stage(elf("wrong CPU", 0x3e, 0x00))
	if !strings.Contains(a.activate(false), "architecture mismatch") || a.read(a.manager) != string(old) {
		t.Fatal("wrong CPU accepted")
	}
}

func TestFirstBootKernelRequestIsPrivateAndConsumedOnce(t *testing.T) {
	a := newActivation(t)
	a.activate(true)
	dir := filepath.Join(a.root, "etc/openweir/mihomo-kernel")
	pending := filepath.Join(dir, ".first-install-pending")
	info, err := os.Stat(pending)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal(info, err)
	}
	if err := os.Rename(pending, filepath.Join(dir, ".first-install-attempted")); err != nil {
		t.Fatal(err)
	}
	a.activate(true)
	if exists(pending) {
		t.Fatal("request repeated")
	}
}

func TestInterruptedVerifiedCandidateRecoversOffline(t *testing.T) {
	a := newActivation(t)
	os.RemoveAll(a.payload)
	a.write(a.manager, elf("old manager"))
	if err := os.Link(a.manager, filepath.Join(a.runtime, ".manager.previous")); err != nil {
		t.Fatal(err)
	}
	a.write(filepath.Join(a.runtime, ".manager.next"), a.binary)
	a.activate(true)
	if a.read(a.manager) != string(a.binary) || exists(filepath.Join(a.runtime, ".manager.previous")) ||
		exists(filepath.Join(a.runtime, ".manager.next")) {
		t.Fatal("candidate not recovered")
	}
}

func TestInterruptedPartialWriteKeepsOldManagerWithBoundedStorage(t *testing.T) {
	a := newActivation(t)
	os.RemoveAll(a.payload)
	old := elf("old manager")
	for range 2 {
		a.write(filepath.Join(a.runtime, ".manager.previous"), old)
		a.write(a.manager, []byte("damaged replacement"))
		a.write(filepath.Join(a.runtime, ".manager.next"), []byte("partial"))
		a.activate(false)
		if a.read(a.manager) != string(old) || exists(filepath.Join(a.runtime, ".manager.previous")) ||
			exists(filepath.Join(a.runtime, ".manager.next")) {
			t.Fatal("old manager not restored")
		}
	}
}

func TestUntrustedStageOrCandidateLinkIsRejectedBeforeWriting(t *testing.T) {
	a := newActivation(t)
	os.Chmod(a.payload, 0o777)
	if !strings.Contains(a.activate(false), "unsafe package payload directory") {
		t.Fatal("unsafe payload accepted")
	}
	os.Chmod(a.payload, 0o700)
	victim := filepath.Join(a.root, "unrelated")
	a.write(victim, []byte("preserve"))
	if err := os.Symlink(victim, filepath.Join(a.runtime, ".manager.next")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.activate(false), "invalid installer state") || a.read(victim) != "preserve" {
		t.Fatal("candidate link followed")
	}
}
