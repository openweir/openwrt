package router

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"maps"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openweir/openwrt/internal/kernel"
	"github.com/openweir/openwrt/internal/subscription"
)

const Global = "@global"
const Local = "@default"
const TProxyPort = 19762
const MixedPort = 19763
const DNSPort = 19764

type Network struct {
	Family6   bool
	DNS       bool
	Method    string
	Resolver  string
	LAN       map[string][]netip.Prefix
	Interface string
	BlockQUIC bool
	FakeIP    bool
	// Zero values mean the defaults: sniffing and tuning on, built-in upstreams.
	NoSniff, NoConcurrent, NoUnifiedDelay bool
	Domestic, Foreign                     []string
}
type DeviceRule struct {
	Address string `json:"address"`
	Target  string `json:"target"`
}
type CustomRule struct {
	Note    string `json:"note,omitempty"`
	ID      string `json:"id"`
	Enabled *bool  `json:"enabled,omitempty"`
	subscription.Rule
}
type Policy struct {
	AutoFailover      bool         `json:"auto_failover,omitempty"`
	DefaultDirect     bool         `json:"default_direct,omitempty"`
	RecordConnections *bool        `json:"record_connections,omitempty"`
	Groups            []LocalGroup `json:"groups,omitempty"`
	Telegram          *Telegram    `json:"telegram,omitempty"`
	Devices           []DeviceRule `json:"devices,omitempty"`
	Rules             []CustomRule `json:"rules,omitempty"`
}
type obj = map[string]any

func stringOption(m obj, k string) string { s, _ := m[k].(string); return s }
func choice(m map[string]string, id string, members []string) (string, error) {
	s := m[id]
	if s != "" && !slices.Contains(members, s) {
		return "", fmt.Errorf("saved member unavailable for %s", id)
	}
	return s, nil
}

// Native Mihomo names are the stable per-source IDs, independent of display names.
func coreTarget(s string) string {
	switch s {
	case subscription.Direct:
		return "DIRECT"
	case subscription.Reject:
		return "REJECT"
	default:
		return s
	}
}

var digestName = regexp.MustCompile("^[a-f0-9]{64}$")

const dnsDomesticSet = "openweir-dns-cn"

// Names that must keep real addresses: LAN, time sync, connectivity checks and STUN.
var fakeIPFilter = []string{"*.lan", "*.local", "*.localdomain", "*.home.arpa", "localhost.ptlink", "+.ntp.org", "time.*.com", "time.*.gov", "+.pool.ntp.org",
	"+.msftconnecttest.com", "+.msftncsi.com", "connectivitycheck.gstatic.com", "captive.apple.com", "+.stun.*.*", "+.stun.*.*.*", "probe.openweir.invalid"}

func Compile(i Intent, p subscription.Profile, c kernel.TargetCapabilities, n Network, secret string) ([]byte, error) {
	if p.SchemaVersion != subscription.SchemaVersion || i.Source == "" || i.Source != p.Source {
		return nil, errors.New("no authorized primary source")
	}
	if c.Control != kernel.Controller {
		return nil, errors.New("unsupported core control interface")
	}
	if len(secret) < 16 {
		return nil, errors.New("missing control secret")
	}
	if !validMode(i.Mode) {
		return nil, errors.New("unknown routing mode")
	}
	if n.Method != "tproxy" && n.Method != "tun" {
		return nil, errors.New("unknown interception method")
	}
	if n.Method == "tun" && !c.TUN || n.Method == "tproxy" && !c.TProxy {
		return nil, errors.New("selected release lacks the configured interception method")
	}
	domesticDNS, foreignDNS := n.Domestic, n.Foreign
	if len(domesticDNS) == 0 {
		domesticDNS = DomesticDNS
	}
	if len(foreignDNS) == 0 {
		foreignDNS = ForeignDNS
	}
	resolver, err := netip.ParseAddr(n.Resolver)
	if err != nil || resolver.IsLoopback() || resolver.IsUnspecified() {
		return nil, errors.New("missing WAN DNS resolver")
	}
	config := obj{"mode": "rule", "mixed-port": MixedPort, "allow-lan": false, "external-controller": "127.0.0.1:19761", "secret": secret, "ipv6": n.Family6,
		"log-level": "warning", "profile": obj{"store-selected": false, "store-fake-ip": false}, "geodata-mode": true, "geo-auto-update": false,
		"hosts": obj{"probe.openweir.invalid": "192.0.2.1"}, "dns": obj{"enable": true, "listen": "", "enhanced-mode": "redir-host", "use-hosts": true,
			"use-system-hosts": false, "ipv6": n.Family6, "default-nameserver": []string{resolver.String(), "223.5.5.5", "119.29.29.29"},
			// Foreign names resolve over encrypted DNS through the proxy; mainland
			// names and node hostnames use domestic resolvers so CDNs stay local.
			"nameserver": foreignDNS, "proxy-server-nameserver": domesticDNS, "direct-nameserver": domesticDNS, "respect-rules": true,
			"nameserver-policy": obj{"rule-set:" + dnsDomesticSet: domesticDNS}, "fake-ip-range": "172.30.254.1/30"},
		"find-process-mode": "off", "tcp-concurrent": !n.NoConcurrent, "unified-delay": !n.NoUnifiedDelay, "keep-alive-interval": 30}
	// The WAN resolver may return poisoned answers for proxied sites. Dial the
	// sniffed domain so the node resolves it, in every proxy mode.
	config["sniffer"] = obj{"enable": !n.NoSniff, "override-destination": true, "parse-pure-ip": true, "force-dns-mapping": true,
		// Push and smart-home services break when their destination is rewritten.
		"skip-domain": []string{"+.push.apple.com", "Mijia Cloud", "+.mi.com", "+.xiaomi.net", "dlg.io.mi.com"},
		"sniff":       obj{"TLS": obj{"ports": []string{"443", "8443"}}, "HTTP": obj{"ports": []string{"80", "8080"}}, "QUIC": obj{"ports": []string{"443"}}}}
	if n.DNS {
		dns := config["dns"].(obj)
		dns["listen"] = "127.0.0.1:19764"
		// Fake-ip needs devices to resolve through the core, so it follows DNS protection.
		if n.FakeIP {
			dns["enhanced-mode"] = "fake-ip"
			dns["fake-ip-range"] = "198.18.0.1/16"
			dns["fake-ip-filter"] = fakeIPFilter
			config["profile"].(obj)["store-fake-ip"] = true
		}
	}
	// Built-in listeners share a bind address. Keep the diagnostic SOCKS/HTTP
	// socket loopback-only, and bind only the dedicated transparent socket to LAN.
	var listeners []obj
	if n.Method == "tproxy" {
		host := "0.0.0.0"
		if n.Family6 {
			host = "::"
		}
		listeners = append(listeners, obj{"name": "lan-tproxy", "type": "tproxy", "listen": host, "port": TProxyPort, "udp": true})
	} else {
		tun := obj{"enable": true, "device": "owtun0", "stack": "system", "auto-route": false, "auto-redirect": false, "auto-detect-interface": false, "dns-hijack": []string{}, "inet6-address": []string{}}
		if n.Family6 {
			tun["inet6-address"] = []string{"fd7e:5745:4952::1/126"}
		}
		config["tun"] = tun
	}
	proxies := []obj{}
	available := map[string]bool{subscription.Direct: true, subscription.Reject: true}
	targets := maps.Clone(available)
	foreign := map[string]bool{}
	for _, ref := range i.Policy.refs() {
		if ref.Source != i.Source {
			foreign[ref.ID] = true
		}
	}
	var nodes []string
	unsupported := map[string]bool{}
	for _, node := range p.Nodes {
		if node.Special {
			continue
		}
		if incompatible(node, c) != "" {
			unsupported[node.ID] = true
			continue
		}
		if node.ID == "" || available[node.ID] || node.Outbound == nil {
			return nil, errors.New("invalid or duplicate node identity")
		}
		proxy := maps.Clone(node.Outbound)
		proxy["name"] = node.ID
		proxies = append(proxies, proxy)
		available[node.ID] = true
		if !foreign[node.ID] {
			nodes = append(nodes, node.ID)
		}
	}
	if len(nodes) == 0 {
		return nil, errors.New("no compatible general-purpose nodes on this release")
	}
	config["proxies"] = proxies
	groups := []obj{}
	addGroup := func(id, kind string, members []string, opts obj) error {
		native := map[string]string{"selector": "select", "urltest": "url-test", "fallback": "fallback", "loadbalance": "load-balance", "load-balance": "load-balance"}[kind]
		if native == "" {
			return fmt.Errorf("unsupported group type %s", kind)
		}
		usable := []string{}
		for _, member := range members {
			if unsupported[member] {
				continue
			}
			if !available[member] {
				return fmt.Errorf("member unavailable in %s", id)
			}
			usable = append(usable, member)
		}
		if len(usable) == 0 {
			return Issue{"group", id, "no compatible members on this device"}
		}
		g := obj{"type": native, "name": id}
		for _, k := range []string{"url", "interval", "tolerance", "lazy", "timeout", "max-failed-times", "expected-status", "strategy", "disable-udp", "hidden", "icon"} {
			if v, ok := opts[k]; ok {
				g[k] = v
			}
		}
		if raw, ok := g["interval"].(string); ok {
			if d, e := time.ParseDuration(raw); e == nil && d > 0 && d%time.Second == 0 {
				g["interval"] = int64(d / time.Second)
			}
		}
		if native == "select" {
			saved := i.Choices[i.Source][id]
			if saved == "" {
				saved = stringOption(opts, "default")
			}
			if saved != "" {
				pos := slices.Index(usable, saved)
				if pos < 0 {
					return Issue{"group", id, "saved member unavailable on this device"}
				}
				g["default-selected"] = coreTarget(saved)
			}
		}
		for j, v := range usable {
			usable[j] = coreTarget(v)
		}
		g["proxies"] = usable
		groups = append(groups, g)
		targets[id] = true
		available[id] = true
		return nil
	}
	end := p.Final
	if i.Mode == "global" || p.Local {
		end = Local
		if i.Mode == "global" {
			end = Global
		}
		if err := addGroup(end, "selector", nodes, nil); err != nil {
			return nil, err
		}
	} else {
		for _, g := range p.Groups {
			if available[g.ID] || g.ID == "" {
				return nil, errors.New("duplicate group identity")
			}
			available[g.ID] = true
		}
		for _, g := range p.Groups {
			if err := addGroup(g.ID, g.Kind, g.Members, g.Options); err != nil {
				return nil, err
			}
		}
		if end == "" && len(p.Groups) > 0 {
			end = p.Groups[0].ID
		}
	}
	if i.Mode == "smart" {
		for _, g := range i.Policy.Groups {
			if available[g.ID] {
				return nil, errors.New("duplicate local group identity")
			}
			var members []string
			for _, ref := range g.Members {
				members = append(members, ref.ID)
			}
			if err := addGroup(g.ID, "selector", members, nil); err != nil {
				return nil, err
			}
		}
	}
	config["proxy-groups"] = groups
	var rules []string
	if t := i.Policy.Telegram; t != nil {
		relay, extra, err := telegram(*t, p, n)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, relay)
		rules = append(rules, extra...)
	}
	if n.BlockQUIC {
		// Browsers fall back to TCP, where sniffing and routing are reliable.
		rules = append(rules, "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
	}
	if len(listeners) > 0 {
		config["listeners"] = listeners
	}
	for _, prefix := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"} {
		rules = append(rules, "IP-CIDR,"+prefix+",DIRECT,no-resolve")
	}
	providers := map[string]obj{}
	var exceptions []string
	for _, d := range i.Policy.Devices {
		if i.Mode == "global" && d.Target != subscription.Direct {
			continue
		}
		match, err := deviceMatch(d.Address)
		if err != nil {
			return nil, err
		}
		var cond, src string
		if mac, ok := match["source_mac_address"].(string); ok {
			name := macProviderName(mac)
			providers[name] = obj{"type": "file", "format": "text", "behavior": "ipcidr", "path": "./devices/" + name + ".txt"}
			cond = "RULE-SET," + name
			src = ",src"
		} else {
			cond = "SRC-IP-CIDR," + stringOption(match, "source_ip_cidr")
		}
		if d.Target == "@proxy" {
			exceptions = append(exceptions, "NOT,(("+cond+src+"))")
			continue
		}
		if !targets[d.Target] {
			return nil, fmt.Errorf("unavailable device target %s", d.Target)
		}
		rules = append(rules, cond+","+coreTarget(d.Target)+src)
	}
	if i.Mode == "smart" && i.Policy.DefaultDirect {
		conditions := append([]string{"IN-TYPE," + strings.ToUpper(n.Method)}, exceptions...)
		rules = append(rules, logical("AND", conditions)+",DIRECT")
	}
	if i.Mode == "smart" {
		for _, set := range p.BinarySets {
			if !digestName.MatchString(set.SHA256) || filepath.Base(set.Filename()) != set.Filename() {
				return nil, errors.New("invalid rule provider digest")
			}
			format := set.FileFormat()
			if !slices.Contains([]string{"yaml", "mrs", "text"}, format) {
				return nil, errors.New("unsupported rule provider format")
			}
			if _, exists := providers[set.Tag]; exists {
				return nil, errors.New("rule provider name collision")
			}
			providers[set.Tag] = obj{"type": "file", "format": format, "behavior": set.Behavior, "path": "./rulesets/" + set.Filename()}
		}
		addRule := func(r subscription.Rule) error {
			if !targets[r.Target] {
				return fmt.Errorf("unavailable rule target %s", r.Target)
			}
			line, err := nativeRule(r.Match, coreTarget(r.Target))
			if err == nil {
				rules = append(rules, line)
			}
			return err
		}
		for _, r := range i.Policy.Rules {
			if r.Enabled != nil && !*r.Enabled {
				continue
			}
			if err := addRule(r.Rule); err != nil {
				return nil, err
			}
		}
		if p.Local {
			for _, v := range []struct{ tag, behavior string }{{"geosite-cn", "domain"}, {"geoip-cn", "ipcidr"}} {
				providers[v.tag] = obj{"type": "file", "format": "mrs", "behavior": v.behavior, "path": "./builtin/" + v.tag + ".mrs"}
				rules = append(rules, "RULE-SET,"+v.tag+",DIRECT")
			}
		} else {
			for _, r := range p.Rules {
				if _, provided := providers[r.RuleSet]; !provided {
					switch r.RuleSet {
					case subscription.DomesticIPSet:
						providers[r.RuleSet] = obj{"type": "file", "format": "mrs", "behavior": "ipcidr", "path": "./builtin/geoip-cn.mrs"}
					case subscription.DomesticDomainSet:
						providers[r.RuleSet] = obj{"type": "file", "format": "mrs", "behavior": "domain", "path": "./builtin/geosite-cn.mrs"}
					}
				}
				if err := addRule(r); err != nil {
					return nil, err
				}
			}
		}
	}
	if !targets[end] {
		return nil, errors.New("default route has no available group")
	}
	if _, taken := providers[dnsDomesticSet]; !taken {
		providers[dnsDomesticSet] = obj{"type": "file", "format": "mrs", "behavior": "domain", "path": "./builtin/geosite-cn.mrs"}
	}
	config["rule-providers"] = providers
	config["rules"] = append(rules, "MATCH,"+coreTarget(end))
	return yaml.Marshal(config)
}
