package router

import "testing"

func TestDNSModeDefaultsToDnsmasq(t *testing.T) {
	if dnsMode("") != "dnsmasq" || dnsMode("bogus") != "dnsmasq" || dnsMode("firewall") != "firewall" {
		t.Fatal("unexpected DNS mode default")
	}
	if (Preferences{Method: "tproxy", Networks: []string{"lan"}, DNSMode: "x"}).Validate() == nil {
		t.Fatal("accepted unknown DNS mode")
	}
}
