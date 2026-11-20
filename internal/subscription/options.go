package subscription

import (
	"sort"
	"strings"
)

// RequiredOptions names the capabilities a signed release must explicitly
// advertise for this node. Never include a password, address or arbitrary raw
// option value in a capability identifier.
func (n Node) RequiredOptions() []string {
	m := n.Outbound
	var options []string
	switch n.Protocol {
	case "vless", "vmess", "trojan", "anytls":
		t := field(m, "network")
		if t == "" || t == "tcp" {
			t = "raw"
		}
		options = append(options, t)
		if m["tls"] == true {
			options = append(options, "tls")
		}
		if m["reality-opts"] != nil {
			options = append(options, "reality")
		}
		if m["flow"] == "xtls-rprx-vision" {
			options = append(options, "vision")
		}
	case "snell":
		v, _ := integer(m["version"])
		if v == 4 || v == 5 {
			options = append(options, "v5")
			if mode := field(object(m["obfs-opts"]), "mode"); mode != "" && mode != "none" {
				options = append(options, "v5-obfs")
				if mode == "tls" {
					options = append(options, "v5-obfs-tls")
				}
			}
		} else if v == 6 {
			options = append(options, "v6")
			for _, k := range []string{"userkey", "mode", "reuse"} {
				if x := m[k]; x != nil && x != "" && x != false {
					options = append(options, "v6-"+k)
				}
			}
		}
	case "naive":
		if m["quic"] == true {
			options = append(options, "http3-connect")
		} else {
			options = append(options, "http2-connect")
		}
		if m["udp-over-tcp"] == true {
			if v, _ := integer(m["udp-over-tcp-version"]); v == 1 {
				options = append(options, "uot-v1")
			} else {
				options = append(options, "uot-v2")
			}
		}
	case "mieru":
		if strings.EqualFold(field(m, "transport"), "UDP") {
			options = append(options, "udp-underlay")
		} else {
			options = append(options, "tcp-underlay")
		}
	case "nowhere":
		if m["network"] == "udp" {
			options = append(options, "nw3-quic", "datagram")
		} else {
			options = append(options, "nw3-tls")
		}
	}
	sort.Strings(options)
	return options
}

func confirmedLoss(p Profile) bool {
	if p.Final == Reject {
		return true
	}
	for _, r := range p.Rules {
		if r.Target == Reject {
			return true
		}
	}
	return false
}
