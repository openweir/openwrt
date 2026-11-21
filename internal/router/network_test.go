package router

import (
	"errors"
	"net/netip"
	"slices"
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

func TestWANResolverIsOptional(t *testing.T) {
	for in, want := range map[string]string{
		"": "",
		"# Interface wan\nnameserver fe80::1%pppoe-wan\nnameserver 127.0.0.1\nnameserver 192.168.1.1\nnameserver 192.0.2.53\n": "192.168.1.1",
		"# Interface wan6\nnameserver 2001:db8::53\n": "2001:db8::53",
	} {
		if got := wanResolver([]byte(in)); got != want {
			t.Fatalf("%q: %q, want %q", in, got, want)
		}
	}
	p := baseProfile(t, "p")
	i := initial()
	i.Source = p.Source
	n := Network{Method: "tproxy", LAN: map[string][]netip.Prefix{"br-lan": {netip.MustParsePrefix("192.168.3.1/24")}}}
	nameservers := func(n Network) []string {
		var r []string
		for _, v := range configForTest(t, i, p, n)["dns"].(map[string]any)["default-nameserver"].([]any) {
			r = append(r, v.(string))
		}
		return r
	}
	if got := nameservers(n); !slices.Equal(got, []string{"223.5.5.5", "119.29.29.29"}) {
		t.Fatal("start without a WAN resolver", got)
	}
	n.Resolver = "192.0.2.53"
	if got := nameservers(n); !slices.Equal(got, []string{"192.0.2.53", "223.5.5.5", "119.29.29.29"}) {
		t.Fatal(got)
	}
	// A resolver that comes or goes reloads the core in place.
	if networkKey(i, n) != networkKey(i, Network{Method: n.Method, LAN: n.LAN}) {
		t.Fatal("resolver change forces a restart")
	}
}
