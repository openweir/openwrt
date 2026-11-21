package router

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type Preferences struct {
	UpdateHours  int      `json:"update_hours"`
	Enabled      bool     `json:"enabled"`
	Method       string   `json:"method"`
	DNS          bool     `json:"dns"`
	DNSIntercept bool     `json:"dns_intercept"`
	FailOpen     *bool    `json:"fail_open,omitempty"`
	LocalProxy   *bool    `json:"local_proxy,omitempty"`
	BlockQUIC    *bool    `json:"block_quic,omitempty"`
	FakeIP       *bool    `json:"fake_ip,omitempty"`
	Sniff        *bool    `json:"sniff,omitempty"`
	Concurrent   *bool    `json:"tcp_concurrent,omitempty"`
	UnifiedDelay *bool    `json:"unified_delay,omitempty"`
	BypassCN     *bool    `json:"bypass_cn,omitempty"`
	CommonPorts  *bool    `json:"common_ports,omitempty"`
	DNSDomestic  []string `json:"dns_domestic,omitempty"`
	DNSForeign   []string `json:"dns_foreign,omitempty"`
	IPv6         bool     `json:"ipv6"`
	Networks     []string `json:"networks"`
}

var networkName = regexp.MustCompile("^[A-Za-z0-9_]{1,32}$")

func (p Preferences) Validate() error {
	if p.UpdateHours < 0 || p.UpdateHours > 720 {
		return errors.New("invalid subscription refresh period")
	}
	if p.Method != "tproxy" && p.Method != "tun" {
		return errors.New("unsupported network method")
	}
	for _, list := range [][]string{p.DNSDomestic, p.DNSForeign} {
		if list != nil && (len(list) == 0 || len(list) > 4) {
			return errors.New("choose one to four DNS upstreams")
		}
		for _, v := range list {
			if !validUpstream(v) {
				return errors.New("invalid DNS upstream")
			}
		}
	}
	if len(p.Networks) == 0 || len(p.Networks) > 16 {
		return errors.New("choose at least one LAN network")
	}
	seen := map[string]bool{}
	for _, n := range p.Networks {
		if !networkName.MatchString(n) || n == "wan" || n == "wan6" || n == "loopback" || seen[n] {
			return errors.New("invalid or duplicate LAN network")
		}
		seen[n] = true
	}
	return nil
}

// SameNetwork reports whether two preference sets produce the same takeover.
func (p Preferences) SameNetwork(o Preferences) bool {
	return p.Method == o.Method && p.DNS == o.DNS && p.DNSIntercept == o.DNSIntercept && p.IPv6 == o.IPv6 && slices.Equal(p.Networks, o.Networks) &&
		sameBit(p.FailOpen, o.FailOpen) && sameBit(p.LocalProxy, o.LocalProxy) && sameBit(p.BlockQUIC, o.BlockQUIC) && sameBit(p.FakeIP, o.FakeIP) &&
		sameBit(p.Sniff, o.Sniff) && sameBit(p.Concurrent, o.Concurrent) && sameBit(p.UnifiedDelay, o.UnifiedDelay) &&
		sameBit(p.BypassCN, o.BypassCN) && sameBit(p.CommonPorts, o.CommonPorts) &&
		sameList(p.DNSDomestic, o.DNSDomestic) && sameList(p.DNSForeign, o.DNSForeign)
}

// An omitted list keeps its saved value.
func sameList(a, b []string) bool { return a == nil || b == nil || slices.Equal(a, b) }

// An omitted switch keeps its saved value.
func sameBit(a, b *bool) bool { return a == nil || b == nil || *a == *b }
func ReadPreferences(ctx context.Context) (Preferences, error) {
	p := Preferences{Enabled: uci(ctx, "enabled") == "1", Method: uci(ctx, "method"), DNS: uci(ctx, "dns") == "1", IPv6: uci(ctx, "ipv6") != "0", Networks: strings.Fields(uci(ctx, "network"))}
	p.UpdateHours, _ = strconv.Atoi(uci(ctx, "update_hours"))
	p.DNSIntercept = uci(ctx, "dns_intercept") == "1"
	failOpen := uci(ctx, "fail_open") != "0"
	p.FailOpen = &failOpen
	local := uci(ctx, "local_proxy") != "0"
	p.LocalProxy = &local
	quic := uci(ctx, "block_quic") != "0"
	p.BlockQUIC = &quic
	fake := uci(ctx, "fake_ip") != "0"
	p.FakeIP = &fake
	sniff := uci(ctx, "sniff") != "0"
	p.Sniff = &sniff
	concurrent := uci(ctx, "tcp_concurrent") != "0"
	p.Concurrent = &concurrent
	unified := uci(ctx, "unified_delay") != "0"
	p.UnifiedDelay = &unified
	// Both narrow what the firewall hands to the core, so they stay off unless chosen.
	cn := uci(ctx, "bypass_cn") == "1"
	p.BypassCN = &cn
	ports := uci(ctx, "common_ports") == "1"
	p.CommonPorts = &ports
	p.DNSDomestic = upstreams(uci(ctx, "dns_domestic"), DomesticDNS)
	p.DNSForeign = upstreams(uci(ctx, "dns_foreign"), ForeignDNS)
	return p, p.Validate()
}
func SavePreferences(ctx context.Context, p Preferences) error {
	if e := p.Validate(); e != nil {
		return e
	}
	tmp, e := os.MkdirTemp(RunDir, "uci-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	bit := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	var b strings.Builder
	if p.FailOpen != nil {
		b.WriteString("set openweir.main.fail_open='" + bit(*p.FailOpen) + "'\n")
	}
	if p.LocalProxy != nil {
		b.WriteString("set openweir.main.local_proxy='" + bit(*p.LocalProxy) + "'\n")
	}
	for k, v := range map[string]*bool{"sniff": p.Sniff, "tcp_concurrent": p.Concurrent, "unified_delay": p.UnifiedDelay, "bypass_cn": p.BypassCN, "common_ports": p.CommonPorts} {
		if v != nil {
			b.WriteString("set openweir.main." + k + "='" + bit(*v) + "'\n")
		}
	}
	for k, list := range map[string][]string{"dns_domestic": p.DNSDomestic, "dns_foreign": p.DNSForeign} {
		if list != nil {
			b.WriteString("delete openweir.main." + k + "\n")
			for _, v := range list {
				b.WriteString("add_list openweir.main." + k + "='" + v + "'\n")
			}
		}
	}
	if p.FakeIP != nil {
		b.WriteString("set openweir.main.fake_ip='" + bit(*p.FakeIP) + "'\n")
	}
	if p.BlockQUIC != nil {
		b.WriteString("set openweir.main.block_quic='" + bit(*p.BlockQUIC) + "'\n")
	}
	for k, v := range map[string]string{"update_hours": strconv.Itoa(p.UpdateHours), "enabled": bit(p.Enabled), "method": p.Method, "dns": bit(p.DNS), "dns_intercept": bit(p.DNSIntercept), "ipv6": bit(p.IPv6)} {
		b.WriteString("set openweir.main." + k + "='" + v + "'\n")
	}
	b.WriteString("delete openweir.main.network\n")
	for _, v := range p.Networks {
		b.WriteString("add_list openweir.main.network='" + v + "'\n")
	}
	b.WriteString("commit openweir\n")
	// -t stages changes in this job's directory and commits to /etc/config.
	// -P enables UCI's no-commit mode and would discard the update on cleanup.
	cmd := exec.CommandContext(ctx, "uci", "-q", "-t", tmp, "batch")
	cmd.Stdin = strings.NewReader(b.String())
	if cmd.Run() != nil {
		return errors.New("could not save network preferences")
	}
	return nil
}

var upstreamPattern = regexp.MustCompile(`^((https|tls|quic)://[A-Za-z0-9.:\[\]_-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?|[0-9.]+|[0-9A-Fa-f:]+)$`)

// validUpstream accepts DoH, DoT, DoQ or a plain resolver address; quotes and
// spaces are excluded so the value is safe in UCI and YAML.
func validUpstream(v string) bool { return len(v) <= 200 && upstreamPattern.MatchString(v) }

var (
	DomesticDNS = []string{"https://223.5.5.5/dns-query", "https://120.53.53.53/dns-query"}
	ForeignDNS  = []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}
)

func upstreams(saved string, fallback []string) []string {
	var r []string
	for _, v := range strings.Fields(saved) {
		if validUpstream(v) && len(r) < 4 {
			r = append(r, v)
		}
	}
	if len(r) == 0 {
		return slices.Clone(fallback)
	}
	return r
}
