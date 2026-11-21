package proxyspec

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNowhereOutboundUsesMihomoFields(t *testing.T) {
	n, e := SingBox(map[string]any{"type": "nowhere", "server": "n.example", "server_port": 443, "credential": strings.Repeat("a", 32), "net": "udp", "morph": false})
	if e != nil || n["password"] != strings.Repeat("a", 32) || n["network"] != "udp" || n["morph"] != false {
		t.Fatal(e)
	}
}
func TestFileAccessAndIncompleteConversionsAreRejected(t *testing.T) {
	base := map[string]any{"type": "naive", "server": "node.example", "port": 443}
	for k, v := range map[string]any{"interface-name": "wan", "routing-mark": 255, "certificate": "/tmp/local.pem", "dialer-proxy": 1, "plugin-path": "/usr/sbin/tool", "smux": map[string]any{"dialer-proxy": "other"}} {
		base[k] = v
		if _, e := Native(base); !errors.Is(e, ErrOption) {
			t.Fatalf("accepted %s", k)
		}
		delete(base, k)
	}
	if _, e := SingBox(map[string]any{"type": "vless", "uuid": "test", "server": "edge.example", "server_port": 443, "tls": map[string]any{"enabled": true, "certificate_path": "/etc/private"}}); !errors.Is(e, ErrOption) {
		t.Fatal(e)
	}
	v, e := Native(map[string]any{"type": "anytls", "name": "edge", "server": "n.example", "port": 443, "password": "fixture", "reality-opts": map[string]any{"public-key": "a", "short-id": "b"}})
	if e != nil || v["name"] != nil || !reflect.DeepEqual(v["reality-opts"], map[string]any{"public-key": "a", "short-id": "b"}) {
		t.Fatal("native option was lost", e)
	}
}

func TestChainsKeepTheirDialerName(t *testing.T) {
	v, e := Native(map[string]any{"type": "http", "name": "exit", "server": "exit.example", "port": 443, "dialer-proxy": "Front"})
	if e != nil || v["dialer-proxy"] != "Front" {
		t.Fatal("chained node rejected", e)
	}
	if !Unsafe("interface-name", "wan") || !Unsafe("routing-mark", 1) || Unsafe("dialer-proxy", "Front") || Unsafe("udp", true) {
		t.Fatal("router-safety policy changed")
	}
	// Safety alone: completeness is the converter's concern.
	if Safe(map[string]any{"type": "vless", "server": "v.example"}) != nil || !errors.Is(Safe(map[string]any{"type": "direct"}), ErrProtocol) {
		t.Fatal("policy mixes safety with completeness")
	}
}
