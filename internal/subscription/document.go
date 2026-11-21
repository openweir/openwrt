package subscription

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/openweir/openwrt/internal/proxyspec"
	"gopkg.in/yaml.v3"
)

func set(words string) map[string]bool {
	out := map[string]bool{}
	for _, v := range strings.Fields(words) {
		out[v] = true
	}
	return out
}

var native = set("vless vmess trojan shadowsocks shadowsocksr anytls hysteria2 tuic naive http socks snell mieru nowhere mtproxy")

func list(v any) []any            { a, _ := v.([]any); return a }
func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func textlist(v any) ([]string, bool) {
	if s, ok := v.(string); ok {
		return []string{s}, true
	}
	if ss, ok := v.([]string); ok {
		return ss, true
	}
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	r := make([]string, 0, len(a))
	for _, x := range a {
		s, ok := x.(string)
		if !ok || s == "" {
			return nil, false
		}
		r = append(r, s)
	}
	return r, true
}
func parseJSON(p *Profile, body []byte) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var m map[string]any
	if err := d.Decode(&m); err != nil {
		return errors.New("invalid_json")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid_json")
	}
	if _, ok := m["proxies"]; ok {
		return parseClash(p, m)
	}
	return errors.New("unsupported_format")
}
func unsafeOption(v any, depth int) bool {
	if depth > 40 {
		return true
	}
	switch o := v.(type) {
	case map[string]any:
		for k, x := range o {
			if strings.HasSuffix(k, "_path") || strings.HasSuffix(k, "_file") || k == "path" && depth == 0 || k == "detour" || k == "routing_mark" || k == "bind_interface" || k == "network_namespace" || k == "network_strategy" || k == "protect_path" || k == "bind_address" || strings.HasPrefix(k, "inet4_bind") || strings.HasPrefix(k, "inet6_bind") || k == "client_certificate" || k == "client_key" || k == "external_controller" || unsafeOption(x, depth+1) {
				return true
			}
		}
	case []any:
		for _, x := range o {
			if unsafeOption(x, depth+1) {
				return true
			}
		}
	}
	return false
}
func addNative(p *Profile, name string, m map[string]any) error {
	kind := field(m, "type")
	if !native[kind] || unsafeOption(m, 0) {
		return errors.New("unsupported_node")
	}
	var required []string
	switch kind {
	case "vless", "vmess":
		required = []string{"uuid"}
	case "shadowsocks":
		required = []string{"method", "password"}
	case "shadowsocksr":
		required = []string{"method", "password", "protocol", "obfs"}
	case "trojan", "anytls", "hysteria2":
		required = []string{"password"}
	case "tuic":
		required = []string{"uuid", "password"}
	case "mieru":
		required = []string{"username", "password"}
	case "nowhere":
		required = []string{"credential"}
	case "mtproxy":
		return proxyspec.ErrProtocol
	case "snell":
		// Snell profiles specify a PSK and a separate optional v6 ClientID.
		if _, extra := m["password"]; extra {
			if _, present := m["psk"]; !present {
				return errSnellCredential
			}
			delete(m, "password")
			p.notice("nonstandard_snell_field", name, false)
		}

	}
	for _, k := range required {
		if field(m, k) == "" {
			return errors.New("node_missing_credential")
		}
	}
	if kind == "http" && object(m["tls"])["enabled"] == true {
		kind = "https"
	}
	if kind == "socks" {
		if v := field(m, "version"); v != "" && v != "5" {
			return errors.New("unsupported_node")
		}
		kind = "socks5"
	}
	return p.add(name, kind, m)
}
func resolve(p *Profile) {
	names := map[string]string{Direct: Direct, Reject: Reject}
	ambiguous := map[string]bool{}
	add := func(name, id string) {
		if old := names[name]; old != "" && old != id {
			ambiguous[name] = true
		}
		names[name] = id
	}
	special := map[string]bool{}
	seen := map[string]bool{}
	unique := p.Nodes[:0]
	for _, n := range p.Nodes {
		if n.Special {
			special[n.ID] = true
		}
		add(n.Name, n.ID)
		if !seen[n.ID] {
			seen[n.ID] = true
			unique = append(unique, n)
		}
	}
	p.Nodes = unique
	for i := range p.Groups {
		g := &p.Groups[i]
		if seen["group:"+g.Name] {
			ambiguous[g.Name] = true
		}
		seen["group:"+g.Name] = true
		g.ID = ref("group", []string{p.Source, g.Name})
		add(g.Name, g.ID)
	}
	bad := func(name string) bool { return ambiguous[name] || names[name] == "" }
	p.chains(names, bad, special)
	for i := range p.Groups {
		g := &p.Groups[i]
		if ambiguous[g.Name] {
			p.notice("ambiguous_group", g.Name, false)
		}
		var retained []string
		for _, m := range g.Members {
			if bad(m) || special[names[m]] {
				p.notice("mihomo_unavailable_member", g.Name, false)
				continue
			}
			retained = append(retained, names[m])
		}
		g.Members = retained
		if len(g.Members) == 0 {
			p.notice("invalid_group", g.Name, false)
		}
		if v, ok := g.Options["default"].(string); ok {
			if bad(v) {
				p.notice("mihomo_unavailable_member", g.Name, false)
				delete(g.Options, "default")
			} else {
				g.Options["default"] = names[v]
			}
		}
	}
	if names["DIRECT"] == "" {
		names["DIRECT"] = Direct
	}
	if names["REJECT"] == "" {
		names["REJECT"] = Reject
	}
	groups := map[string]Group{}
	for _, g := range p.Groups {
		groups[g.ID] = g
	}
	marks := map[string]uint8{}
	var visit func(string) bool
	visit = func(id string) bool {
		if marks[id] == 1 {
			return true
		}
		if marks[id] == 2 {
			return false
		}
		marks[id] = 1
		for _, m := range groups[id].Members {
			if _, ok := groups[m]; ok && visit(m) {
				return true
			}
		}
		marks[id] = 2
		return false
	}
	for _, g := range p.Groups {
		if visit(g.ID) {
			p.notice("cyclic_group", g.Name, false)
			break
		}
	}
	target := func(t, at string) string {
		if bad(t) || special[names[t]] {
			p.notice("unresolved_target", at, t == Reject || strings.EqualFold(t, "REJECT"))
			return ""
		}
		id := names[t]
		if strings.HasPrefix(id, "node:") {
			gid := ref("group", []string{p.Source, "single", id})
			if _, exists := groups[gid]; !exists {
				g := Group{ID: gid, Name: t, Kind: "selector", Members: []string{id}}
				p.Groups = append(p.Groups, g)
				groups[gid] = g
			}
			return gid
		}
		return id
	}
	for i := range p.Rules {
		p.Rules[i].Target = target(p.Rules[i].Target, fmt.Sprintf("rule %d", i+1))
	}
	if p.Final != "" {
		p.Final = target(p.Final, "final")
	}
}

// chains resolves each node's dialer-proxy to the ID of a node or group of the same document,
// as the core names them. The core refuses a whole configuration over a chain that names
// nothing or can lead back to its own node, so such a node is dropped instead, and so is
// every chain through it; references to it then resolve as to any other missing node.
func (p *Profile) chains(names map[string]string, bad func(string) bool, special map[string]bool) {
	via := map[string]string{}
	drop := map[string]string{}
	for _, n := range p.Nodes {
		name := n.Dialer()
		switch id := names[name]; {
		case name == "":
		case clashTarget(name) == Direct:
			delete(n.Outbound, "dialer-proxy")
		case bad(name) || special[id] || id == Reject:
			drop[n.ID] = "dialer_proxy_unavailable"
		default:
			via[n.ID] = id
		}
	}
	// A group in a chain may pick any member, so a member that leads back counts as a cycle.
	edges := map[string][]string{}
	for n, id := range via {
		edges[n] = []string{id}
	}
	for _, g := range p.Groups {
		for _, m := range g.Members {
			if !bad(m) {
				edges[g.ID] = append(edges[g.ID], names[m])
			}
		}
	}
	// Tarjan's strongly connected components: a chained node on a cycle can reach itself.
	index, low := map[string]int{}, map[string]int{}
	onStack := map[string]bool{}
	var stack []string
	var connect func(string)
	connect = func(v string) {
		index[v], low[v] = len(index), len(index)
		stack = append(stack, v)
		onStack[v] = true
		for _, w := range edges[v] {
			if _, seen := index[w]; !seen {
				connect(w)
				low[v] = min(low[v], low[w])
			} else if onStack[w] {
				low[v] = min(low[v], index[w])
			}
		}
		if low[v] != index[v] {
			return
		}
		top := len(stack) - 1
		for stack[top] != v {
			top--
		}
		component := stack[top:]
		stack = stack[:top]
		for _, w := range component {
			onStack[w] = false
		}
		if len(component) > 1 || slices.Contains(edges[v], v) {
			for _, w := range component {
				if via[w] != "" {
					drop[w] = "dialer_proxy_cycle"
				}
			}
		}
	}
	for _, n := range p.Nodes {
		if _, seen := index[n.ID]; via[n.ID] != "" && !seen {
			connect(n.ID)
		}
	}
	for changed := true; changed; {
		changed = false
		for n, id := range via {
			if drop[n] == "" && drop[id] != "" {
				drop[n] = "dialer_proxy_unavailable"
				changed = true
			}
		}
	}
	kept := p.Nodes[:0]
	for _, n := range p.Nodes {
		if code := drop[n.ID]; code != "" {
			p.notice(code, n.Name, false)
			continue
		}
		if id := via[n.ID]; id != "" {
			n.Outbound["dialer-proxy"] = id
		}
		kept = append(kept, n)
	}
	p.Nodes = kept
	for name, id := range names {
		if drop[id] != "" {
			delete(names, name)
		}
	}
}
func hasYAMLRoot(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "proxies:") || strings.HasPrefix(line, "proxy-providers:") {
			return true
		}
	}
	return false
}
func parseYAML(p *Profile, body []byte) error {
	var m map[string]any
	d := yaml.NewDecoder(bytes.NewReader(body))
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid_yaml")
	}
	return parseClash(p, m)
}
func parseClash(p *Profile, m map[string]any) error {
	p.Format = "clash"
	for _, k := range []string{"external-controller", "external-controller-tls", "external-controller-unix", "external-controller-pipe", "external-ui", "external-ui-url", "secret", "tun", "listeners", "iptables", "ebpf", "tunnels"} {
		if _, ok := m[k]; ok {
			p.notice("mihomo_router_field_ignored", k, false)
		}
	}
	if _, exists := m["script"]; exists {
		p.notice("script", "script", true)
	}
	for _, k := range []string{"proxy-providers", "rule-providers"} {
		if len(object(m[k])) > 0 {
			if k == "rule-providers" {
				p.notice("mihomo_unsupported_rule_set", k, false)
			} else {
				p.notice("provider_required", k, false)
			}
		}
	}
	if len(list(m["proxies"])) > maxNodes || len(list(m["proxy-groups"])) > maxNodes {
		return errors.New("node_limit")
	}
	for i, item := range list(m["proxies"]) {
		proxy := object(item)
		name := field(proxy, "name")
		out, err := proxyspec.Native(proxy)
		if err == nil {
			err = p.addProxy(name, proxyProtocol(out), out)
		}
		if err != nil {
			p.notice(err.Error(), first(publicLabel(name, ""), fmt.Sprintf("proxy %d", i+1)), false)
		}
	}
	for _, item := range list(m["proxy-groups"]) {
		v := object(item)
		name := field(v, "name")
		g := Group{Name: name, Options: map[string]any{}}
		switch field(v, "type") {
		case "select":
			g.Kind = "selector"
		case "url-test":
			g.Kind = "urltest"
		case "fallback":
			g.Kind = "fallback"
		case "load-balance":
			g.Kind = "loadbalance"
		default:
			p.notice("unsupported_group", name, false)
			continue
		}
		members, ok := textlist(v["proxies"])
		if !safeLabel(name) || !ok || len(members) == 0 {
			p.notice("invalid_group", name, false)
			continue
		}
		for _, v := range members {
			g.Members = append(g.Members, clashTarget(v))
		}
		for k, x := range v {
			switch k {
			case "name", "type", "proxies":
			case "hidden":
				g.Hidden, _ = x.(bool)
			case "icon":
			// External display resources are controlled by the client.
			case "url", "tolerance", "strategy", "lazy", "expected-status", "timeout", "max-failed-times", "disable-udp":
				g.Options[k] = x
			case "interval":
				g.Options[k] = fmt.Sprint(x) + "s"
			default:
				p.notice("unsupported_group_option", name, false)
			}
		}
		p.Groups = append(p.Groups, g)
	}
	if len(list(m["rules"])) > maxRules {
		return errors.New("rule_limit")
	}
	for i, e := range list(m["rules"]) {
		s, _ := e.(string)
		if kind, name, _, ok := geoRule(s); ok && !clashDefaultGeo(m, kind) {
			p.notice("rule_provider_custom_geo", kind+" "+name, strings.Contains(strings.ToUpper(s), "REJECT"))
			continue
		}
		parseMihomoRule(p, s, i+1)
	}
	return nil
}
func clashTarget(s string) string {
	switch s {
	case "DIRECT":
		return Direct
	case "REJECT":
		return Reject
	}
	return s
}
func parseRule(p *Profile, s string, line int) {
	f := strings.Split(s, ",")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	at := fmt.Sprintf("rule %d", line)
	danger := strings.Contains(strings.ToUpper(s), "REJECT") || strings.Contains(strings.ToUpper(s), "DROP")
	if len(f) == 2 && (strings.EqualFold(f[0], "MATCH") || strings.EqualFold(f[0], "FINAL")) {
		if p.Final != "" {
			p.notice("unreachable_rule", at, danger)
		}
		p.Final = clashTarget(f[1])
		return
	}
	if p.Final != "" || len(f) != 3 {
		p.notice("unsupported_rule", at, danger)
		return
	}
	field := map[string]string{"DOMAIN": "domain", "HOST": "domain", "DOMAIN-SUFFIX": "domain_suffix", "HOST-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword", "HOST-KEYWORD": "domain_keyword", "IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr", "IP6-CIDR": "ip_cidr", "SRC-IP-CIDR": "source_ip_cidr", "DST-PORT": "port", "SRC-PORT": "source_port", "NETWORK": "network"}[strings.ToUpper(f[0])]
	if field == "" || f[1] == "" || strings.EqualFold(f[2], "REJECT-DROP") {
		p.notice("unsupported_rule", at, danger)
		return
	}
	var val any = f[1]
	if field == "port" || field == "source_port" {
		n, ok := integer(f[1])
		if !ok || n < 1 || n > 65535 {
			p.notice("invalid_rule", at, danger)
			return
		}
		val = n
	}
	p.Rules = append(p.Rules, Rule{Match: map[string]any{field: val}, Target: clashTarget(f[2])})
}
