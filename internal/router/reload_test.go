package router

import "testing"

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
