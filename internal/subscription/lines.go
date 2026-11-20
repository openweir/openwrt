package subscription

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func hasLineConfig(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		t := strings.ToLower(strings.TrimSpace(line))
		if t == "[proxy]" || t == "[server_local]" || t == "[general]" || t == "[proxy group]" || strings.HasPrefix(t, "shadowsocks=") || strings.HasPrefix(t, "vmess=") || strings.HasPrefix(t, "trojan=") || strings.HasPrefix(t, "http=") || strings.HasPrefix(t, "socks5=") || strings.HasPrefix(t, "vless=") {
			return true
		}
	}
	return false
}
func comma(s string) ([]string, error) {
	r := csv.NewReader(strings.NewReader(s))
	r.TrimLeadingSpace = true
	r.LazyQuotes = true
	a, e := r.Read()
	for i := range a {
		a[i] = strings.TrimSpace(a[i])
		a[i] = strings.Trim(a[i], "\"")
	}
	return a, e
}
func parseLines(p *Profile, s string) error {
	p.Format = "surge-loon"
	section := ""
	rules := 0
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		at := fmt.Sprintf("line %d", i+1)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "server_local" || section == "policy" {
				p.Format = "quantumult-x"
			}
			continue
		}
		switch section {
		case "", "proxy", "server_local":
			name, spec, ok := strings.Cut(line, "=")
			if !ok {
				p.notice("invalid_node", at, false)
				continue
			}
			parts, err := comma(spec)
			if err != nil || len(parts) == 0 {
				p.notice("invalid_node", at, false)
				continue
			}
			quan := section != "proxy"
			if quan {
				p.Format = "quantumult-x"
			}
			if err := parseLineNode(p, strings.TrimSpace(name), parts, quan); err != nil {
				p.notice(err.Error(), at, false)
			}
		case "proxy group", "policy":
			key, rest, ok := strings.Cut(line, "=")
			if !ok {
				p.notice("invalid_group", at, false)
				continue
			}
			parts, err := comma(rest)
			if err != nil || len(parts) < 2 {
				p.notice("invalid_group", at, false)
				continue
			}
			name, kind := strings.TrimSpace(key), strings.ToLower(parts[0])
			if section == "policy" {
				name, kind = parts[0], strings.ToLower(strings.TrimSpace(key))
			}
			g := Group{Name: name, Kind: map[string]string{"select": "selector", "static": "selector", "url-test": "urltest", "url-latency-benchmark": "urltest", "load-balance": "loadbalance"}[kind], Options: map[string]any{}}
			if !safeLabel(name) || g.Kind == "" {
				p.notice("unsupported_group", at, false)
				continue
			}
			for _, m := range parts[1:] {
				if k, v, option := strings.Cut(m, "="); option {
					switch k {
					case "url":
						g.Options["url"] = v
					case "interval":
						g.Options[k] = v + "s"
					case "tolerance":
						n, ok := integer(v)
						if ok {
							g.Options[k] = n
						} else {
							p.notice("unsupported_group_option", at, false)
						}
					default:
						p.notice("unsupported_group_option", at, false)
					}
					continue
				}
				g.Members = append(g.Members, clashTarget(m))
			}
			p.Groups = append(p.Groups, g)
		case "rule", "rules", "filter_local":
			rules++
			if rules > maxRules {
				return errors.New("rule_limit")
			}
			parseRouterLineRule(p, line, i+1)
		case "general", "dns": // Router owns its DNS and listeners.
		case "script", "rewrite_local", "rewrite_remote", "url rewrite", "map local":
			p.notice("script", at, true)
		default:
			p.notice("unsupported_section", at, strings.Contains(strings.ToUpper(line), "REJECT"))
		}
	}
	return nil
}

const DomesticIPSet = "@openweir-geoip-cn"

func parseRouterLineRule(p *Profile, line string, index int) {
	parts := strings.Split(line, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) == 4 && strings.EqualFold(parts[3], "no-resolve") {
		switch strings.ToUpper(parts[0]) {
		case "IP-CIDR", "IP-CIDR6", "IP6-CIDR", "GEOIP":
			// Transparent LAN capture supplies the original destination IP. These
			// matches do not add any DNS resolution operation.
			parts = parts[:3]
			line = strings.Join(parts, ",")
		}
	}
	if len(parts) == 3 && strings.EqualFold(parts[0], "GEOIP") && strings.EqualFold(parts[1], "CN") && p.Final == "" && !strings.HasPrefix(strings.ToUpper(parts[2]), "REJECT-") {
		p.Rules = append(p.Rules, Rule{Match: map[string]any{"rule_set": DomesticIPSet}, RuleSet: DomesticIPSet, Target: clashTarget(parts[2])})
		return
	}
	parseRule(p, line, index)
}

func parseLineNode(p *Profile, key string, parts []string, quan bool) error {
	m := map[string]any{}
	name := key
	kind := ""
	var tail []string
	if quan {
		kind = strings.ToLower(key)
		h, n, err := net.SplitHostPort(parts[0])
		if err != nil {
			return errNode
		}
		m["server"], m["server_port"] = h, n
		tail = parts[1:]
	} else {
		if len(parts) < 3 {
			return errNode
		}
		kind = strings.ToLower(parts[0])
		m["server"], m["server_port"] = parts[1], parts[2]
		tail = parts[3:]
	}
	tls := map[string]any{}
	options := map[string]string{}
	var pos []string
	for _, s := range tail {
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			pos = append(pos, s)
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(v, "\"")
		if _, dup := options[k]; dup {
			return errOption
		}
		options[k] = v
	}
	if kind == "snell" && options["obfs"] == "tls" {
		return errOption
	}
	if quan {
		name = options["tag"]
	}
	if !safeLabel(name) {
		return errNode
	}
	switch kind {
	case "ss", "shadowsocks":
		m["type"] = "shadowsocks"
		if options["ssr-protocol"] != "" {
			m["type"] = "shadowsocksr"
		}
	case "shadowsocksr":
		m["type"] = "shadowsocksr"
	case "socks5", "socks5-tls":
		m["type"] = "socks"
		m["version"] = "5"
		if kind == "socks5-tls" {
			tls["enabled"] = true
		}
	case "http", "https":
		m["type"] = "http"
		if kind == "https" {
			tls["enabled"] = true
		}
	case "trojan", "anytls", "hysteria2", "tuic", "tuic-v5":
		m["type"] = strings.TrimSuffix(kind, "-v5")
		tls["enabled"] = true
	case "vmess", "vless", "snell":
		m["type"] = kind
	default:
		return errOption
	}
	switch kind {
	case "shadowsocks", "shadowsocksr":
		if len(pos) >= 2 {
			m["method"], m["password"] = pos[0], pos[1]
			pos = pos[2:]
		}
	case "vmess", "vless":
		if len(pos) > 0 {
			m["uuid"] = pos[0]
			pos = pos[1:]
		}
	case "trojan", "anytls":
		if len(pos) > 0 {
			m["password"] = pos[0]
			pos = pos[1:]
		}
	case "http", "https", "socks5", "socks5-tls":
		if len(pos) == 2 {
			m["username"], m["password"] = pos[0], pos[1]
			pos = nil
		}
	}
	if len(pos) != 0 {
		return errOption
	}
	ws := options["ws"] == "true" || options["transport"] == "ws" || options["obfs"] == "ws" || options["obfs"] == "wss"
	for k, v := range options {
		switch k {
		case "tag":
		case "password", "username":
			if kind == "vmess" || kind == "vless" {
				m["uuid"] = v
			} else {
				m[k] = v
			}
		case "method", "encrypt-method":
			if kind == "ss" || kind == "shadowsocks" || kind == "shadowsocksr" {
				m["method"] = v
			} else if kind == "vmess" {
				m["security"] = v
			} else if v != "none" {
				return errOption
			}
		case "uuid", "psk", "mode", "userkey", "flow":
			m[k] = v
		case "vless-flow":
			if kind != "vless" {
				return errOption
			}
			m["flow"] = v
		case "public-key", "short-id", "reality-base64-pubkey", "reality-hex-shortid":
			if kind != "vless" {
				return errOption
			}
		case "version":
			n, ok := integer(v)
			if !ok {
				return errNode
			}
			m[k] = n
		case "udp-relay", "udp":
			if v == "false" {
				m["network"] = "tcp"
			}
		case "tfo", "fast-open", "reuse":
			b, e := strconv.ParseBool(v)
			if e != nil {
				return errNode
			}
			if k == "reuse" {
				m[k] = b
			} else {
				m["tcp_fast_open"] = b
			}
		case "sni", "tls-name", "tls-host":
			tls["server_name"] = v
		case "tls", "over-tls":
			b, e := strconv.ParseBool(v)
			if e != nil {
				return errNode
			}
			tls["enabled"] = b
		case "skip-cert-verify", "tls-verification":
			b, e := strconv.ParseBool(v)
			if e != nil {
				return errNode
			}
			if k == "tls-verification" {
				b = !b
			}
			tls["insecure"] = b
		case "alpn":
			tls["alpn"] = strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' })
		case "vmess-aead":
			if v != "true" {
				return errOption
			}
		case "ssr-protocol", "ssr-protocol-param":
			m[strings.ReplaceAll(strings.TrimPrefix(k, "ssr-"), "-", "_")] = v
		case "obfs":
			if m["type"] == "shadowsocksr" {
				m["obfs"] = v
			} else if kind == "snell" {
				m["obfs_mode"] = v
			} else if v == "over-tls" || v == "wss" {
				tls["enabled"] = true
			} else if v != "ws" {
				return errOption
			}
		case "obfs-host":
			if m["type"] == "shadowsocksr" {
				m["obfs_param"] = v
			} else if kind == "snell" {
				m["obfs_host"] = v
			} else if !ws {
				tls["server_name"] = v
			}
		case "ws", "ws-path", "ws-headers", "obfs-uri", "transport", "path", "host":
			if !ws && !(k == "transport" && v == "tcp") {
				return errOption
			}
		default:
			return errOption
		}
	}
	if pk := first(options["public-key"], options["reality-base64-pubkey"]); pk != "" {
		if tls["enabled"] == false {
			return errOption
		}
		tls["enabled"] = true
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		tls["reality"] = map[string]any{"enabled": true, "public_key": pk, "short_id": first(options["short-id"], options["reality-hex-shortid"])}
	} else if options["short-id"] != "" || options["reality-hex-shortid"] != "" {
		return errNode
	}
	if ws {
		tr := map[string]any{"type": "ws", "path": first(options["ws-path"], options["obfs-uri"], options["path"], "/")}
		host := first(options["host"], options["obfs-host"])
		if h := options["ws-headers"]; h != "" {
			k, v, ok := strings.Cut(h, ":")
			if !ok || !strings.EqualFold(k, "Host") || strings.Contains(h, "|") {
				return errOption
			}
			host = v
		}
		if host != "" {
			tr["headers"] = map[string]any{"Host": host}
		}
		m["transport"] = tr
	}
	if len(tls) > 0 {
		if _, ok := tls["enabled"]; !ok {
			tls["enabled"] = true
		}
		m["tls"] = tls
	}
	return addNative(p, name, m)
}
