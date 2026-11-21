package router

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
)

func uci(ctx context.Context, k string) string {
	b, _ := command(ctx, "uci", "-q", "get", "openweir.main."+k)
	return strings.TrimSpace(string(b))
}

type netifAddress struct {
	Address string `json:"address"`
	Mask    int    `json:"mask"`
}
type netifStatus struct {
	Up        bool           `json:"up"`
	Device    string         `json:"l3_device"`
	V4        []netifAddress `json:"ipv4-address"`
	V6        []netifAddress `json:"ipv6-address"`
	Delegated []struct {
		Local netifAddress `json:"local-address"`
	} `json:"ipv6-prefix-assignment"`
}

func validLANDevice(name string) bool {
	return name != "" && len(name) <= 15 && name != "lo" && strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") == ""
}

// Keep the last applied device precedence available to the firewall if the
// core exits. Smart-mode @proxy exceptions follow explicit device routes,
// just as they do in Compile's default-direct rule.
func deviceGuardPolicy(i Intent) (string, error) {
	var rules, exceptions strings.Builder
	defaultDirect := i.Mode == "smart" && i.Policy.DefaultDirect
	for _, d := range i.Policy.Devices {
		if i.Mode == "global" && d.Target != "@direct" || d.Target == "@proxy" && !defaultDirect {
			continue
		}
		match, err := deviceMatch(d.Address)
		if err != nil {
			return "", err
		}
		family, address := "mac", match["source_mac_address"]
		if raw, ok := match["source_ip_cidr"].(string); ok {
			prefix := netip.MustParsePrefix(raw)
			address = prefix.Masked().String()
			family = "4"
			if prefix.Addr().Is6() {
				family = "6"
			}
		}
		target := "block"
		if d.Target == "@direct" {
			target = "direct"
		}
		dst := &rules
		if d.Target == "@proxy" {
			dst = &exceptions
		}
		fmt.Fprintf(dst, "%s %s %s\n", family, address, target)
	}
	rules.WriteString(exceptions.String())
	if defaultDirect {
		rules.WriteString("default direct\n")
	} else {
		rules.WriteString("default block\n")
	}
	return rules.String(), nil
}
func telegramAllowance(t *Telegram, n Network) (string, string, error) {
	if t == nil {
		return "", "", nil
	}
	if !validLANDevice(t.Interface) || !t.Address.IsValid() || t.Port < 1024 || len(t.Allow) == 0 || len(t.Allow) > 128 {
		return "", "", errors.New("invalid Telegram LAN permission")
	}
	var local netip.Prefix
	for _, p := range n.LAN[t.Interface] {
		if p.Addr() == t.Address {
			local = p
			break
		}
	}
	if !local.IsValid() {
		return "", "", errors.New("Telegram address is not assigned to managed interface")
	}
	parts := make([]string, 0, len(t.Allow))
	for _, p := range t.Allow {
		if !p.IsValid() || !local.Contains(p.Addr()) || p.Bits() < local.Bits() {
			return "", "", errors.New("Telegram range outside managed LAN")
		}
		parts = append(parts, p.Masked().String())
	}
	xtFamily := "4"
	family := "ip"
	if t.Address.Is6() {
		family = "ip6"
		xtFamily = "6"
	}
	var legacy strings.Builder
	// iptables-restore inserts each INPUT rule at the head, so emit the deny first.
	fmt.Fprintf(&legacy, "%s - - %s %d\n", xtFamily, t.Address, t.Port)
	for _, prefix := range parts {
		fmt.Fprintf(&legacy, "%s %s %s %s %d\n", xtFamily, t.Interface, prefix, t.Address, t.Port)
	}
	accept := fmt.Sprintf("iifname %q %s saddr { %s } %s daddr %s tcp dport %d accept comment %q\n", t.Interface, family, strings.Join(parts, ", "), family, t.Address, t.Port, "openweir-owned-v1-input")
	deny := fmt.Sprintf("%s daddr %s tcp dport %d drop comment %q\n", family, t.Address, t.Port, "openweir-owned-v1-input")
	return accept + deny, legacy.String(), nil
}
func interfacePrefixes(n netifStatus) ([]netip.Prefix, error) {
	if !n.Up || !validLANDevice(n.Device) {
		return nil, errors.New("managed LAN interface unavailable")
	}
	res := []netip.Prefix{}
	addresses := append(slices.Clone(n.V4), n.V6...)
	for _, d := range n.Delegated {
		addresses = append(addresses, d.Local)
	}
	for _, v := range addresses {
		ip, err := netip.ParseAddr(v.Address)
		if err != nil || !ip.IsGlobalUnicast() {
			continue
		}
		p := netip.PrefixFrom(ip, v.Mask)
		if p.IsValid() && !slices.Contains(res, p) {
			res = append(res, p)
		}
	}
	if len(res) == 0 {
		return nil, errors.New("managed LAN has no usable address")
	}
	return res, nil
}
func networkOptions(ctx context.Context) (Network, error) {
	n := Network{Method: uci(ctx, "method"), DNS: uci(ctx, "dns") == "1", Family6: uci(ctx, "ipv6") == "1", BlockQUIC: uci(ctx, "block_quic") != "0", FakeIP: uci(ctx, "fake_ip") != "0",
		NoSniff: uci(ctx, "sniff") == "0", NoConcurrent: uci(ctx, "tcp_concurrent") == "0", NoUnifiedDelay: uci(ctx, "unified_delay") == "0",
		Domestic: upstreams(uci(ctx, "dns_domestic"), DomesticDNS), Foreign: upstreams(uci(ctx, "dns_foreign"), ForeignDNS), LAN: map[string][]netip.Prefix{}}
	for _, name := range strings.Fields(uci(ctx, "network")) {
		if strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
			return n, errors.New("invalid managed LAN")
		}
		var status netifStatus
		if err := jsonCmd(ctx, &status, "ubus", "call", "network.interface."+name, "status"); err != nil {
			return n, err
		}
		ps, err := interfacePrefixes(status)
		if err != nil {
			return n, err
		}
		n.LAN[status.Device] = append(n.LAN[status.Device], ps...)
	}
	if len(n.LAN) == 0 {
		return n, errors.New("no managed LAN")
	}
	b, err := os.ReadFile("/tmp/resolv.conf.d/resolv.conf.auto")
	if err != nil {
		return n, errors.New("WAN DNS information unavailable")
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err == nil && addr.IsGlobalUnicast() {
			n.Resolver = addr.String()
			return n, nil
		}
	}
	return n, errors.New("WAN DNS resolver unavailable")
}
