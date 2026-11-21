package router

import (
	"net/netip"
	"testing"
)

func TestGlobalModeTakesOverMainlandAddressesToo(t *testing.T) {
	smart, global := Intent{Mode: "smart"}, Intent{Mode: "global"}
	n := Network{Method: "tproxy", ChinaDirect: true}
	if !chinaShortcut(smart, n) || chinaShortcut(global, n) {
		t.Fatal("the China IP shortcut belongs to smart mode only")
	}
	// Switching modes with the shortcut on re-applies the firewall; without it, the core reloads in place.
	if networkKey(smart, n) == networkKey(global, n) {
		t.Fatal("mode switch kept the shortcut")
	}
	n.ChinaDirect = false
	if networkKey(smart, n) != networkKey(global, n) {
		t.Fatal("mode switch without the shortcut forces a restart")
	}
	failOpen := n
	failOpen.FailOpen = true
	if networkKey(smart, n) == networkKey(smart, failOpen) {
		t.Fatal("fault fallback change kept the old takeover")
	}
}

func TestRotatingIPv6PrefixKeepsAnIPv4OnlyTakeover(t *testing.T) {
	lan := func(v6 string) map[string][]netip.Prefix {
		return map[string][]netip.Prefix{"br-lan": {netip.MustParsePrefix("192.168.1.1/24"), netip.MustParsePrefix(v6)}}
	}
	i := Intent{Mode: "smart"}
	before, after := Network{Method: "tproxy", LAN: lan("240e:1::1/64")}, Network{Method: "tproxy", LAN: lan("240e:2::1/64")}
	if networkKey(i, before) != networkKey(i, after) {
		t.Fatal("a new delegated prefix restarted an IPv4-only takeover")
	}
	before.Family6, after.Family6 = true, true
	if networkKey(i, before) == networkKey(i, after) {
		t.Fatal("a new prefix kept the IPv6 takeover on the old one")
	}
	if len(before.LAN["br-lan"]) != 2 {
		t.Fatal("the key changed the network's own prefixes")
	}
}
