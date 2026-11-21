package router

import "testing"

func TestBypassEntries(t *testing.T) {
	for _, v := range []string{"1.2.3.4", "10.0.0.0/8", "240e::/32", "2001:db8::1"} {
		if !validPrefix(v) {
			t.Fatalf("rejected %s", v)
		}
	}
	for _, v := range []string{"", "1.2.3", "fe80::1%br-lan", "1.2.3.4/33", "x'y"} {
		if validPrefix(v) {
			t.Fatalf("accepted %q", v)
		}
	}
	for _, v := range []string{"22", "6881-6889", "65535"} {
		if !validPorts(v) {
			t.Fatalf("rejected %s", v)
		}
	}
	for _, v := range []string{"0", "65536", "9-1", "01", "1-", "a", "1-2-3"} {
		if validPorts(v) {
			t.Fatalf("accepted %q", v)
		}
	}
}
