// Package proxyspec checks mihomo proxies before they reach the router and maps the
// router's line-config (Surge, Loon, Quantumult X) nodes to them. Subscription formats are
// converted by github.com/openweir/subconv.
package proxyspec

import (
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"
)

var ErrOption = errors.New("unsupported_node")
var ErrProtocol = errors.New("mihomo_protocol_unsupported")

func str(m map[string]any, k string) string { v, _ := m[k].(string); return v }
func obj(v any) map[string]any              { m, _ := v.(map[string]any); return m }
func fields(v map[string]any, aliases map[string]string, out map[string]any) error {
	for k, x := range v {
		dest, ok := aliases[k]
		if !ok {
			return ErrOption
		}
		if dest != "" {
			out[dest] = x
		}
	}
	return nil
}

// Native returns a copy with router-sensitive options excluded by rejecting
// the whole node. In particular a subscription cannot make a proxy read keys
// from the router filesystem or run local dialer hooks.
func Native(v map[string]any) (map[string]any, error) {
	switch str(v, "type") {
	case "http", "ss", "ssr", "socks5", "vless", "vmess", "trojan", "snell", "hysteria", "hysteria2", "tuic", "anytls", "naive", "nowhere", "mieru", "ssh", "wireguard", "juicity":
	default:
		return nil, ErrProtocol
	}
	if unsafe(v, 0) {
		return nil, ErrOption
	}
	kind := str(v, "type")
	for _, key := range requiredCredentials[kind] {
		if str(v, key) == "" {
			if kind == "snell" {
				if v["password"] != nil {
					return nil, errSnellCredential
				}
				return nil, errInvalidCredential
			}
			return nil, errors.New("node_missing_credential")
		}
	}
	if !hostValid(str(v, "server")) {
		return nil, errors.New("invalid_endpoint")
	}
	if _, ok := Port(v["port"]); !ok {
		return nil, errors.New("invalid_endpoint")
	}
	out := maps.Clone(v)
	delete(out, "name")
	return out, nil
}

var requiredCredentials = map[string][]string{
	"vless": {"uuid"}, "vmess": {"uuid"}, "ss": {"cipher", "password"}, "ssr": {"cipher", "password", "protocol", "obfs"}, "snell": {"psk"}, "trojan": {"password"}, "hysteria2": {"password"}, "anytls": {"password"}, "nowhere": {"password"}, "mieru": {"username", "password"},
}

func unsafe(v any, depth int) bool {
	if depth > 32 {
		return true
	}
	switch m := v.(type) {
	case map[string]any:
		for k, x := range m {
			switch k {
			case "interface-name", "routing-mark", "dialer-proxy", "netns", "ip-stack", "ca", "ca-path", "private-key-path", "key-path", "client-cert", "client-key", "wg-opts", "plugin-path":
				return true
			case "certificate":
				if !strings.HasPrefix(str(m, k), "-----BEGIN CERTIFICATE-----") {
					return true
				}
			case "private-key":
				if depth != 0 || str(m, "type") != "wireguard" {
					return true
				}
			}
			if strings.HasSuffix(k, "-file") || strings.HasSuffix(k, "-path") || unsafe(x, depth+1) {
				return true
			}
		}
	case []any:
		for _, x := range m {
			if unsafe(x, depth+1) {
				return true
			}
		}
	}
	return false
}

var simple = map[string]string{
	"server": "server", "server_port": "port", "uuid": "uuid", "username": "username", "password": "password", "flow": "flow", "encryption": "encryption", "version": "version", "quic": "quic", "mode": "mode", "psk": "psk", "userkey": "userkey", "reuse": "reuse", "protocol": "protocol", "protocol_param": "protocol-param", "obfs_param": "obfs-param", "alter_id": "alterId", "security": "cipher", "method": "cipher", "packet_encoding": "packet-encoding", "tcp_fast_open": "tfo", "congestion_control": "congestion-controller", "udp_relay_mode": "udp-relay-mode", "zero_rtt_handshake": "reduce-rtt", "credential": "password", "morph": "morph", "pin": "pin", "sni": "sni", "multiplexing": "multiplexing", "handshake_mode": "handshake-mode", "traffic_pattern": "traffic-pattern", "tag": "",
}

func SingBox(m map[string]any) (map[string]any, error) {
	t := str(m, "type")
	if t == "snell" {
		m = maps.Clone(m)
		if e := normalizeSnell(m); e != nil {
			return nil, e
		}
	}
	switch t {
	case "shadowsocks":
		t = "ss"
	case "shadowsocksr":
		t = "ssr"
	case "socks":
		t = "socks5"
	case "http", "vless", "vmess", "trojan", "snell", "hysteria2", "tuic", "anytls", "naive", "nowhere", "mieru":
	default:
		return nil, ErrProtocol
	}
	o := map[string]any{"type": t}
	for k, v := range m {
		switch k {
		case "type":
		case "network":
			if v == "tcp" {
				o["udp"] = false
			} else if v == "udp" {
				return nil, ErrOption
			} else if t != "mieru" {
				return nil, ErrOption
			}
		case "version":
			if t == "socks5" {
				if fmt.Sprint(v) != "5" {
					return nil, ErrOption
				}
			} else if t == "naive" || t == "http" {
				if fmt.Sprint(v) != "1" && t == "http" || fmt.Sprint(v) != "2" && t == "naive" {
					return nil, ErrOption
				}
			} else {
				o[k] = v
			}
		case "tls":
			if e := tls(t, obj(v), o); e != nil {
				return nil, e
			}
		case "transport":
			if t == "mieru" {
				o["transport"] = strings.ToUpper(fmt.Sprint(v))
			} else if e := transport(obj(v), o); e != nil {
				return nil, e
			}
		case "net":
			if v != "tcp" && v != "udp" {
				return nil, ErrOption
			}
			o["network"] = v
		case "obfs_mode", "obfs_host":
			opts := obj(o["obfs-opts"])
			if opts == nil {
				opts = map[string]any{}
				o["obfs-opts"] = opts
			}
			opts[strings.TrimPrefix(k, "obfs_")] = v
		case "obfs":
			if t == "hysteria2" {
				x := obj(v)
				if len(x) != 2 || str(x, "type") != "salamander" {
					return nil, ErrOption
				}
				o["obfs"] = x["type"]
				o["obfs-password"] = x["password"]
			} else {
				o[k] = v
			}
		case "udp_over_tcp":
			switch x := v.(type) {
			case bool:
				o["udp-over-tcp"] = x
			case map[string]any:
				if e := fields(x, map[string]string{"enabled": "udp-over-tcp", "version": "udp-over-tcp-version"}, o); e != nil {
					return nil, e
				}
			default:
				return nil, ErrOption
			}
		case "plugin":
			if v == "obfs-local" {
				v = "obfs"
			}
			o[k] = v
		case "plugin_opts":
			opts := map[string]any{}
			for _, p := range strings.Split(str(m, k), ";") {
				if p == "" {
					continue
				}
				key, value, ok := strings.Cut(p, "=")
				if t == "ss" && str(m, "plugin") == "obfs-local" {
					if key == "obfs" {
						key = "mode"
					} else if key == "obfs-host" {
						key = "host"
					}
				}
				if !ok {
					opts[key] = true
				} else {
					opts[key] = value
				}
			}
			o["plugin-opts"] = opts
		case "server_ports":
			var ports []string
			switch xs := v.(type) {
			case []string:
				ports = xs
			case []any:
				for _, x := range xs {
					ports = append(ports, fmt.Sprint(x))
				}
			default:
				return nil, ErrOption
			}
			o["ports"] = strings.ReplaceAll(strings.Join(ports, ","), ":", "-")
		case "hop_interval", "heartbeat":
			dur, e := time.ParseDuration(fmt.Sprint(v))
			if e != nil || dur <= 0 {
				return nil, ErrOption
			}
			if k == "heartbeat" {
				o["heartbeat-interval"] = dur.Milliseconds()
			} else {
				if dur%time.Second != 0 {
					return nil, ErrOption
				}
				o["hop-interval"] = int(dur / time.Second)
			}
		case "port_bindings":
			var b map[string]any
			switch a := v.(type) {
			case []map[string]any:
				if len(a) == 1 {
					b = a[0]
				}
			case []any:
				if len(a) == 1 {
					b = obj(a[0])
				}
			}
			if b == nil {
				return nil, ErrOption
			}
			carrier := str(b, "protocol")
			if carrier != "UDP" && carrier != "TCP" {
				return nil, ErrOption
			}
			o["transport"] = carrier
			if x := str(b, "port_range"); x != "" {
				o["port-range"] = x
			}
		default:
			dest, ok := simple[k]
			if !ok {
				return nil, ErrOption
			}
			if dest != "" {
				o[dest] = v
			}
		}
	}
	if t == "vmess" && o["cipher"] == nil {
		o["cipher"] = "auto"
	}
	return Native(o)
}

func tls(t string, x, o map[string]any) error {
	if x == nil {
		return ErrOption
	}
	for k, v := range x {
		switch k {
		case "enabled":
			if t == "http" || t == "vless" || t == "vmess" || t == "socks5" {
				o["tls"] = v
			} else if v == false {
				return ErrOption
			}
		case "server_name":
			if t == "vless" || t == "vmess" {
				o["servername"] = v
			} else {
				o["sni"] = v
			}
		case "insecure":
			o["skip-cert-verify"] = v
		case "alpn":
			o["alpn"] = v
		case "certificate":
			s, ok := v.(string)
			if !ok {
				return ErrOption
			}
			o["certificate"] = s
		case "utls":
			z := obj(v)
			if len(z) > 2 || z["enabled"] != true || str(z, "fingerprint") == "" {
				return ErrOption
			}
			o["client-fingerprint"] = z["fingerprint"]
		case "reality":
			z := obj(v)
			if z["enabled"] != true {
				return ErrOption
			}
			opts := map[string]any{}
			if err := fields(z, map[string]string{"enabled": "", "public_key": "public-key", "short_id": "short-id"}, opts); err != nil {
				return err
			}
			o["reality-opts"] = opts
		default:
			return ErrOption
		}
	}
	return nil
}

func transport(x, o map[string]any) error {
	t := str(x, "type")
	opts := map[string]any{}
	switch t {
	case "tcp":
	case "ws", "grpc", "http", "xhttp":
	case "httpupgrade":
		t = "ws"
		opts["v2ray-http-upgrade"] = true
	default:
		return ErrOption
	}
	for k, v := range x {
		switch k {
		case "type":
		case "service_name":
			if t != "grpc" {
				return ErrOption
			}
			opts["grpc-service-name"] = v
		case "host":
			if str(x, "type") == "httpupgrade" {
				opts["headers"] = map[string]any{"Host": v}
			} else {
				opts[k] = v
			}
		case "path", "headers", "mode":
			opts[k] = v
		case "max_early_data":
			opts["max-early-data"] = v
		case "early_data_header_name":
			opts["early-data-header-name"] = v
		default:
			return ErrOption
		}
	}
	o["network"] = t
	if len(opts) > 0 {
		o[t+"-opts"] = opts
	}
	return nil
}

func Port(v any) (int, bool) {
	p, e := strconv.Atoi(fmt.Sprint(v))
	return p, e == nil && p >= 1 && p <= 65535
}
