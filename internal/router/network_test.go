package router

import (
	"errors"
	"testing"
)

func TestManagedLANSkipsInterfacesThatAreDown(t *testing.T) {
	status := map[string]netifStatus{
		"lan":    {Up: true, Device: "br-lan", V4: []netifAddress{{"192.168.1.1", 24}}},
		"guest":  {}, // a guest Wi-Fi switched off
		"iot":    {Up: true, Device: "br-iot"},
		"v6only": {Up: true, Device: "br-v6", V6: []netifAddress{{"2001:db8:5::1", 64}}},
	}
	lookup := func(name string) (netifStatus, error) {
		s, ok := status[name]
		if !ok {
			return s, errors.New("ubus: not found")
		}
		return s, nil
	}
	all := []string{"guest", "lan", "iot", "v6only", "removed"}
	lan, e := managedLAN(all, false, lookup)
	if e != nil || len(lan) != 1 || lan["br-lan"][0].String() != "192.168.1.1/24" {
		t.Fatal("one unusable LAN blocked the others", lan, e)
	}
	// An IPv6-only LAN counts only where IPv6 is taken over, as the helper probes it.
	if lan, e = managedLAN(all, true, lookup); e != nil || len(lan) != 2 || lan["br-v6"] == nil {
		t.Fatal(lan, e)
	}
	if _, e = managedLAN([]string{"guest", "iot", "removed"}, true, lookup); e == nil {
		t.Fatal("took over without a usable LAN")
	}
	if _, e = managedLAN(nil, true, lookup); e == nil || e.Error() != "no managed LAN" {
		t.Fatal(e)
	}
	if _, e = managedLAN([]string{"lan", "lan;x"}, true, lookup); e == nil || e.Error() != "invalid managed LAN" {
		t.Fatal(e)
	}
}
