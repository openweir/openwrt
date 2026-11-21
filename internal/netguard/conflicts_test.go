package netguard

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// What the network script writes with DNS protection on.
const dnsInjection = "# OpenWeir managed upstream\nno-resolv\nserver=127.0.0.1#19764\nserver=/probe.openweir.invalid/127.0.0.1#19764\nrebind-domain-ok=/probe.openweir.invalid/\n"

func TestOwnershipDetection(t *testing.T) {
	c := collector{seen: map[Resource]bool{}, own: ownership{activeNft: true}}
	nft := `{"nftables":[{"table":{"family":"inet","name":"openweir","comment":"openweir-owned-v1"}},{"table":{"family":"inet","name":"v2raya"}},{"rule":{"family":"ip6","table":"fw4","expr":[{"jump":{"target":"PSW2_DNS"}}]}}]}`
	if e := c.nft([]byte(nft)); e != nil {
		t.Fatal(e)
	}
	c.xt("ip6tables", []byte(":OPENCLASH - [0:0]\n-A OUTPUT -j OPENCLASH\n"))
	c.routes("ipv6", []byte("32765: from all fwmark 0x4f57/0xffff lookup 100\n"))
	c.routes("ipv4", []byte("local default dev lo table 21998\n"))
	if !c.seen[Resource{"nft", "inet table v2raya", "v2raya"}] || !c.seen[Resource{"nft", "ip6 jump passwall2", "passwall2"}] || !c.seen[Resource{"xtables", "ip6tables openclash", "openclash"}] {
		t.Fatal(c.sorted())
	}
	if c.seen[Resource{"nft", "inet openweir (unknown owner)", ""}] {
		t.Fatal("mistook owned table for foreign table")
	}
	if len(c.seen) != 5 {
		t.Fatal(c.sorted())
	}
}
func TestConfirmOnlyTheInspectedConflict(t *testing.T) {
	ctx := context.Background()
	var stopped []string
	now := time.Now()
	res := []Resource{{"service", "passwall", "passwall"}}
	c := Checker{Dir: t.TempDir(), Scan: func(context.Context) []Resource { return res }, Stop: func(_ context.Context, s string) error { stopped = append(stopped, s); return nil }, Now: func() time.Time { return now }}
	first, e := c.Check(ctx, "")
	if e != nil || !first.Blocked || first.Token == "" || len(stopped) != 0 {
		t.Fatal(first, e)
	}
	recheck, _ := c.Check(ctx, "")
	if first.Token != recheck.Token {
		t.Fatal("unexpected token churn")
	}
	res = append(res, Resource{"listener", "tcp/19761", ""})
	if _, e = c.Check(ctx, first.Token); e == nil || len(stopped) > 0 {
		t.Fatal("resource changes failed to invalidate consent")
	}
	fresh, _ := c.Check(ctx, "")
	r, e := c.Check(ctx, fresh.Token)
	if e != nil || !r.Blocked || !reflect.DeepEqual(stopped, []string{"passwall"}) {
		t.Fatal(r, e, stopped)
	}
	if _, e = c.Check(ctx, fresh.Token); e == nil {
		t.Fatal("permit reused")
	}
	fresh, _ = c.Check(ctx, "")
	now = now.Add(6 * time.Minute)
	if _, e = c.Check(ctx, fresh.Token); e == nil {
		t.Fatal("expired permit accepted")
	}
	fresh, _ = c.Check(ctx, "")
	c.Stop = func(context.Context, string) error { return errors.New("init script failed") }
	if r, e = c.Check(ctx, fresh.Token); e == nil || !r.Blocked {
		t.Fatal(r, e)
	}
}

func TestOwnedRouteRequiresJournalAndExactSelectors(t *testing.T) {
	o := ownership{routes: map[string]string{"-4": "tproxy", "-6": "tproxy"}}
	for _, tc := range []struct {
		family, line string
		expected     bool
	}{
		{"-4", "21998: from all fwmark 0x4f57/0xffff lookup 21998 proto 199", true},
		{"-4", "2 default dev lo table 21998 proto 199 scope 254", true},
		{"-6", "2 default dev lo table 21998 proto 199 metric 1024 pref medium", true},
		{"-4", "21998: from all fwmark 0x4f57/0xffff iif br-other lookup 21998 proto 199", false},
		{"-4", "21998: from all fwmark 0x4f57/0xffff lookup 21998 proto 198", false},
		{"-4", "2 default dev lo table 21998 proto 199 scope 254 src 192.0.2.1", false},
		{"-4", "local default dev tun0 table 21998 proto 199 scope host", false},
	} {
		if got := o.reservedRoute(tc.family, strings.Fields(tc.line)); got != tc.expected {
			t.Errorf("%s: %v", tc.line, got)
		}
	}
	journal := t.TempDir()
	dns := t.TempDir()
	dir := filepath.Join(journal, "route4")
	if err := os.WriteFile(dir, []byte("tproxy\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal, "dns"), []byte(dns+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dns, "99-openweir-upstream.conf")
	o = networkOwnership(journal)
	if o.dnsFile(path, []byte(dnsInjection)) || len(o.routes) != 0 {
		t.Fatal("accepted an inactive journal")
	}
	if err := os.WriteFile(filepath.Join(journal, "owned"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	o = networkOwnership(journal)
	if !o.dnsFile(path, []byte(dnsInjection)) || o.dnsFile(path, []byte(dnsInjection+"server=127.0.0.1#80\n")) || o.dnsFile(filepath.Join(t.TempDir(), filepath.Base(path)), []byte(dnsInjection)) || o.dnsFile(filepath.Join(dns, "other.conf"), []byte(dnsInjection)) {
		t.Fatal("incorrect DNS ownership")
	}
	if o.routes["-4"] != "tproxy" || o.routes["-6"] != "" {
		t.Fatal("cross-family ownership", o.routes)
	}
}

func TestSupervisedCoreAndOwnedDescriptors(t *testing.T) {
	proc := t.TempDir()
	write := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	manager := filepath.Join(proc, "openweird")
	write(manager, "manager")
	link(manager, filepath.Join(proc, "100", "exe"))
	write(filepath.Join(proc, "100", "cmdline"), manager+"\x00serve\x00")
	write(filepath.Join(proc, "101", "status"), "PPid:\t100\n")
	write(filepath.Join(proc, "102", "status"), "PPid:\t101\n")
	id := strings.Repeat("af", 16)
	core := "/etc/openweir/mihomo-kernel/slots/" + id + "/mihomo-linux-arm64/mihomo"
	cfg := "/etc/openweir/mihomo-kernel/configs/" + id + ".yaml"
	args := []byte(core + "\x00-d\x00/var/run/openweir/mihomo\x00-f\x00" + cfg + "\x00")
	if !supervisedCore(proc, "102", core, args, manager) {
		t.Fatal("supervised core lost")
	}
	if supervisedCore(proc, "103", core, args, manager) || supervisedCore(proc, "102", core, bytes.ReplaceAll(args, []byte(cfg), []byte("/tmp/other.json")), manager) {
		t.Fatal("accepted foreign launch")
	}
	write(filepath.Join(proc, "100", "cmdline"), manager+"\x00guard\x00")
	if supervisedCore(proc, "102", core, args, manager) {
		t.Fatal("wrong supervisor role")
	}
	o := networkOwnership(t.TempDir())
	dir := filepath.Join(proc, "102")
	link("socket:[1234]", filepath.Join(dir, "fd", "3"))
	link("/dev/net/tun", filepath.Join(dir, "fd", "4"))
	write(filepath.Join(dir, "fdinfo", "4"), "iff:\tother0\n")
	o.collectDescriptors(dir)
	if o.tun || !o.sockets["1234"] {
		t.Fatal("mistook another TUN device", o)
	}
	write(filepath.Join(dir, "fdinfo", "4"), "iff:\towtun0\n")
	o.collectDescriptors(dir)
	if !o.tun {
		t.Fatal("owned TUN fd unrecognized")
	}
	write(filepath.Join(proc, "net", "tcp"), "1: 0100007F:4D31 00:0 0A 0:0 0:0 0 1000 0 1234\n")
	write(filepath.Join(proc, "net", "udp"), "")
	c := collector{map[Resource]bool{}, o}
	c.ports(proc)
	if len(c.seen) != 0 {
		t.Fatal(c.sorted())
	}
	write(filepath.Join(proc, "net", "tcp"), "1: 0100007F:4D31 00:0 0A 0:0 0:0 0 1000 0 1234\n2: 0200007F:4D31 00:0 0A 0:0 0:0 0 1000 0 5678\n")
	c.ports(proc)
	if !c.seen[Resource{"listener", "tcp/19761", ""}] {
		t.Fatal("concurrent listener was ignored", c.sorted())
	}
}

func TestFirewallOwnershipChecksForeignRuleInsideOwnChain(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "hold"), 0700); err != nil {
		t.Fatal(err)
	}
	holdFile := filepath.Join(root, "hold", "fw3.4.active")
	snapshot := "-N OW_HOLD\n-A OW_HOLD -i br-lan -p tcp -m comment --comment openweir-fault-v1 -j DROP\n"
	if err := os.WriteFile(holdFile, []byte(snapshot), 0600); err != nil {
		t.Fatal(err)
	}
	c := collector{seen: map[Resource]bool{}, own: networkOwnership(root)}
	save := "*mangle\n:OW_HOLD - [0:0]\n-A OW_HOLD -i br-lan -p tcp -m comment --comment \"openweir-fault-v1\" -j DROP\n"
	c.xt("iptables-save", []byte(save))
	if len(c.seen) != 0 {
		t.Fatal(c.sorted())
	}
	c.xt("iptables-save", []byte(save+"-A OW_HOLD -i br-guest -p tcp -m comment --comment openweir-fault-v1 -j DROP\n"))
	if !c.seen[Resource{"xtables", "iptables-save OW_HOLD (unknown owner)", ""}] {
		t.Fatal("changed rule ignored", c.sorted())
	}
	c.seen = map[Resource]bool{}
	c.xt("ip6tables-save", []byte(save))
	if len(c.seen) == 0 {
		t.Fatal("wrong address family")
	}
	c.seen = map[Resource]bool{}
	c.nft([]byte(`{"nftables":[{"table":{"name":"openweir","family":"inet","comment":"openweir-owned-v1"}},{"table":{"name":"openweir_hold","family":"inet","comment":"openweir-fault-v1"}}]}`))
	if len(c.seen) != 2 {
		t.Fatal("owner comment without matching journal", c.sorted())
	}
}

func TestTUNAndHoldRoutesNeedTheirIndependentOwners(t *testing.T) {
	o := ownership{routes: map[string]string{"-4": "tun", "-6": "tun"}}
	for _, test := range []struct{ family, iface, fallback string }{
		{"-4", "default dev owtun0 table 21998 proto 199 scope 253", "8 default table 21998 proto 199 metric 32760"},
		{"-6", "default dev owtun0 table 21998 proto 199 metric 1024 pref medium", "8 default dev lo table 21998 proto 199 metric 32760 pref medium"},
	} {
		for _, tun := range []bool{false, true} {
			for _, guarded := range []bool{false, true} {
				o.tun, o.guarded = tun, guarded
				if o.reservedRoute(test.family, strings.Fields(test.iface)) != tun || o.reservedRoute(test.family, strings.Fields(test.fallback)) != guarded {
					t.Fatal(test, tun, guarded)
				}
			}
		}
	}
	rule := "21998: from all fwmark 0x4f57/0xffff lookup 21998 proto 199\n"
	c := collector{seen: map[Resource]bool{}, own: o}
	c.routes("-4", []byte(rule+rule))
	if len(c.seen) != 1 {
		t.Fatal("duplicate RPDB entry was ignored")
	}
}

func TestOwnDNSVariants(t *testing.T) {
	for _, s := range []string{dnsInjection, dnsInjection + "filter-AAAA\n", "# OpenWeir managed upstream\nfilter-AAAA\n"} {
		if !ownDNS([]byte(s)) {
			t.Fatalf("own file rejected: %q", s)
		}
	}
	for _, s := range []string{"no-resolv\n", dnsInjection + "server=127.0.0.1#80\n", "# OpenWeir managed upstream\nfilter-aaaa\n"} {
		if ownDNS([]byte(s)) {
			t.Fatalf("foreign file accepted: %q", s)
		}
	}
}
