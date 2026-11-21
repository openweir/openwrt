package subscription

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const maxProviderBody = 2 << 20
const maxProviders = 96

// Embedded URLs are selected by the document, unlike an administrator's
// subscription URL. Resolve and dial the inspected IP, including after redirects.
func publicProviderTransport() *http.Transport {
	return providerTransport(net.DefaultResolver.LookupIPAddr, (&net.Dialer{Timeout: 5 * time.Second}).DialContext)
}

func providerTransport(lookup lookupFunc, dial dialFunc) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialResolved(ctx, network, address, lookup, dial, true)
	}
	return tr
}

// dialResolved dials the addresses it resolved itself. With public, a host with any
// address outside the public internet is refused before anything is dialed.
func dialResolved(ctx context.Context, network, address string, lookup lookupFunc, dial dialFunc, public bool) (net.Conn, error) {
	h, p, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	ips, e := lookup(ctx, h)
	if e != nil {
		return nil, e
	}
	for _, ip := range ips {
		if public && (!ip.IP.IsGlobalUnicast() || ip.IP.IsPrivate() || ip.IP.IsLoopback() || ip.IP.IsLinkLocalUnicast() || ip.IP.IsLinkLocalMulticast() || ip.IP.IsUnspecified() || ip.IP.To4() != nil && ip.IP.To4()[0] == 100 && (ip.IP.To4()[1]&192) == 64) {
			return nil, errors.New("private_provider_address")
		}
	}
	for _, ip := range ips {
		c, err := dial(ctx, network, net.JoinHostPort(ip.IP.String(), p))
		e = err
		if err == nil {
			return c, nil
		}
	}
	if e != nil {
		return nil, e
	}
	return nil, errors.New("provider_unreachable")
}

type providers struct {
	trustedOrigin string
	trusted       Fetcher
	binary        []BinarySet
	f             Fetcher
	ctx           context.Context
	cache         map[string][]byte
	notices       []Notice
}

type providerInput struct {
	raw, kind string
	limit     int64
	header    http.Header
}

// key identifies a download: the same URL with other headers may serve other content.
func (i providerInput) key() string {
	if len(i.header) == 0 {
		return i.raw
	}
	return i.raw + "\x00" + digest(i.header)
}

func (s *providers) download(ctx context.Context, input providerInput) ([]byte, error) {
	raw := input.raw
	client := s.f
	trusted := false
	if strings.HasPrefix(raw, s.trustedOrigin+"/api/v1/app/proxy/subscriptions/rulesets/") && s.trustedOrigin != "" {
		u, err := webURL(raw, true)
		if err != nil {
			return nil, errors.New("invalid_provider_url")
		}
		rest := strings.TrimPrefix(u.EscapedPath(), "/api/v1/app/proxy/subscriptions/rulesets/")
		id, format, found := strings.Cut(rest, "/")
		if found && validTarget(id) && validTarget(format) && u.RawQuery == "" {
			client = s.trusted
			trusted = true
		}
	}
	// Even for the configured platform, an embedded provider receives no bearer
	// or cookies, only the headers its document gave it. The same-origin
	// allowlist also forbids redirects.
	client.header = input.header
	r, e := client.request(ctx, "GET", raw, nil, "", "OpenWeir", trusted, input.limit)
	if e != nil {
		return nil, providerRequestCause(e)
	}
	if r.status != http.StatusOK {
		return nil, fmt.Errorf("provider_http_%d", r.status)
	}
	return r.body, nil
}

// Only the downloads run in parallel. Expansion still applies the original
// order. The aggregate size limit applies to all unique URLs in this refresh.
const providerWorkers = 3

func (s *providers) prefetchInputs(inputs []providerInput, budget int) error {
	seen := make(map[string]providerInput)
	for _, input := range inputs {
		if _, err := webURL(input.raw, true); err != nil {
			return providerFailure(input.kind, input.raw, errors.New("invalid_provider_url"))
		}
		if prev, ok := seen[input.key()]; !ok || input.limit < prev.limit {
			seen[input.key()] = input
		}
	}
	jobs := make(chan providerInput, len(seen))
	for _, input := range seen {
		jobs <- input
	}
	close(jobs)
	ctx, stop := context.WithCancel(s.ctx)
	defer stop()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failure error
	total := 0
	for range min(providerWorkers, len(seen)) {
		wg.Go(func() {
			for input := range jobs {
				if ctx.Err() != nil {
					return
				}
				b, err := s.download(ctx, input)
				mu.Lock()
				if err == nil && total+len(b) > budget {
					err = errors.New("provider_size_limit")
				}
				if err != nil && failure == nil {
					failure = providerFailure(input.kind, input.raw, err)
					stop()
				}
				if failure == nil {
					s.cache[input.key()] = b
					total += len(b)
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if failure != nil {
		return failure
	}
	return s.ctx.Err()
}

func clashRuleHTTP(v map[string]any) bool {
	format, behavior := field(v, "format"), field(v, "behavior")
	return field(v, "type") == "http" && providerKeys(v, "type url path interval format behavior") &&
		(format == "" || format == "yaml" || format == "text" || format == "mrs") &&
		(behavior == "classical" || behavior == "domain" || behavior == "ipcidr")
}

// expandSourceProviders downloads a document's providers into it. It also returns the rule
// sets the document gained and notices about provider options the router did not follow.
func (f Fetcher) expandSourceProviders(ctx context.Context, b []byte, origin string) ([]byte, []BinarySet, []Notice, error) {
	if len(b) > MaxBody {
		return nil, nil, nil, errors.New("subscription_size_limit")
	}
	if !bytes.Contains(b, []byte("proxy-providers")) && !bytes.Contains(b, []byte("rule-providers")) && !hasYAMLRoot(string(b)) && !bytes.Contains(b, []byte(`"proxies"`)) {
		return b, nil, nil, nil
	}
	var m map[string]any
	s := &providers{trustedOrigin: strings.TrimSuffix(providerAddress(origin), "/"), trusted: f, ctx: ctx, cache: map[string][]byte{}}
	tr := publicProviderTransport()
	defer tr.CloseIdleConnections()
	s.f.Client = &http.Client{Transport: tr, Timeout: 15 * time.Second}
	s.f.Fallback, s.f.egress, s.f.embedded = f.Fallback, f.egress, true
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
			return nil, nil, nil, errors.New("invalid_json")
		}
	} else if hasYAMLRoot(string(trimmed)) {
		d := yaml.NewDecoder(bytes.NewReader(b))
		if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
			return nil, nil, nil, errors.New("invalid_yaml")
		}
	} else {
		return b, nil, nil, nil
	}
	normalizeProviderAddresses(m)
	if r := f.providerReceipt; r != nil && r.Key != "" {
		if ttl := providerLifetime(m); ttl > 0 {
			r.Expires = r.Checked.Add(ttl)
		}
	}
	if e := s.clash(m); e != nil {
		return nil, nil, nil, e
	}
	total := 0
	for _, rs := range s.binary {
		total += len(rs.Data)
		if total > MaxBody {
			return nil, nil, nil, errors.New("provider_size_limit")
		}
	}
	out, e := json.Marshal(m)
	if e != nil || len(out) > MaxBody {
		return nil, nil, nil, errors.New("expanded_subscription_limit")
	}
	return out, s.binary, s.notices, nil
}
func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
func (s *providers) clash(m map[string]any) error {
	pp := object(m["proxy-providers"])
	rp := object(m["rule-providers"])
	if len(pp)+len(rp) > maxProviders {
		return errors.New("provider_limit")
	}
	var inputs []providerInput
	expandable := map[string]proxyProvider{}
	for _, k := range sortedKeys(pp) {
		if p, ok := s.proxyProvider(k, object(pp[k])); ok {
			expandable[k] = p
			if p.input.raw != "" {
				inputs = append(inputs, p.input)
			}
		}
	}
	for _, entry := range rp {
		if v := object(entry); clashRuleHTTP(v) {
			inputs = append(inputs, providerInput{raw: field(v, "url"), kind: "rule", limit: MaxBody})
		}
	}
	if err := s.prefetchInputs(inputs, maxSetMaterialization); err != nil {
		return err
	}
	names := map[string][]any{}
	var standalone []any
	for _, n := range list(m["proxies"]) {
		standalone = append(standalone, object(n)["name"])
	}
	allProviderNames := sortedKeys(pp)

	nodes := list(m["proxies"])
	if nodes == nil {
		nodes = []any{}
	}
	for _, k := range sortedKeys(pp) {
		p, ok := expandable[k]
		if !ok {
			continue
		}
		var doc struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if p.input.raw == "" {
			for _, elem := range list(object(pp[k])["payload"]) {
				n := object(elem)
				if n == nil {
					return errors.New("invalid_proxy_provider")
				}
				doc.Proxies = append(doc.Proxies, n)
			}
		} else if yaml.Unmarshal(s.cache[p.input.key()], &doc) != nil || doc.Proxies == nil {
			return providerFailure("node", p.input.raw, errors.New("invalid_proxy_provider"))
		}
		doc.Proxies = p.shape(doc.Proxies)
		if len(nodes)+len(doc.Proxies) > maxNodes {
			return errors.New("node_limit")
		}
		members := []any{}
		for _, n := range doc.Proxies {
			members = append(members, n["name"])
			nodes = append(nodes, n)
		}
		names[k] = members
		delete(pp, k)
	}
	m["proxies"] = nodes
	for _, item := range list(m["proxy-groups"]) {
		g := object(item)
		if g["include-all"] == true {
			g["include-all-providers"] = true
			g["include-all-proxies"] = true
			delete(g, "include-all")
		}
		if g["include-all-providers"] == true {
			g["use"] = allProviderNames
			delete(g, "include-all-providers")
		}
		if g["use"] == nil && g["include-all-proxies"] != true {
			continue
		}
		var use []string
		if g["use"] != nil {
			var ok bool
			use, ok = textlist(g["use"])
			if !ok {
				continue
			}
		}
		matches, ok := groupFilter(g)
		if !ok {
			continue
		}
		members := list(g["proxies"])
		if g["include-all-proxies"] == true {
			for _, x := range standalone {
				if name, ok := x.(string); ok && matches(name) {
					members = append(members, name)
				}
			}
			delete(g, "include-all-proxies")
		}
		complete := true
		for _, k := range use {
			n, ok := names[k]
			if !ok {
				complete = false
				break
			}
			if len(members)+len(n) > maxNodes {
				return errors.New("node_limit")
			}
			for _, x := range n {
				if name, ok := x.(string); ok && matches(name) {
					members = append(members, name)
				}
			}
		}
		if complete {
			delete(g, "use")
			delete(g, "filter")
			delete(g, "exclude-filter")
			if len(members) == 0 {
				if fallback := field(g, "empty-fallback"); fallback != "" {
					members = append(members, fallback)
				}
			}
			delete(g, "empty-fallback")
			g["proxies"] = members
		}
	}
	// Provider names only address rules: template paths never become local paths.
	for _, name := range sortedKeys(rp) {
		v := object(rp[name])
		format := field(v, "format")
		behavior := field(v, "behavior")
		var raw []byte
		switch {
		case clashRuleHTTP(v):
			raw = s.cache[field(v, "url")]
		case field(v, "type") == "file" && providerKeys(v, "type path behavior format"):
			var e error
			raw, e = s.trusted.localClashSet(field(v, "path"))
			if e != nil {
				continue
			}

		case field(v, "type") == "inline" && providerKeys(v, "type behavior payload format"):
			if format != "" && format != "yaml" {
				continue
			}
			var e error
			raw, e = yaml.Marshal(map[string]any{"payload": v["payload"]})
			if e != nil {
				return errRulePayload
			}
		default:
			continue
		}
		if name == DomesticIPSet || name == DomesticDomainSet {
			return errRulePayload
		}
		set, err := mihomoSet(name, format, behavior, raw)
		if err != nil {
			return providerFailure("rule", field(v, "url"), err)
		}
		s.binary = append(s.binary, set)
		delete(rp, name)
	}

	return nil
}
func providerKeys(m map[string]any, keys string) bool {
	allowed := set(keys)
	for k := range m {
		if !allowed[k] {
			return false
		}
	}
	return true
}
func groupFilter(g map[string]any) (func(string) bool, bool) {
	compile := func(k string) ([]*regexp.Regexp, bool) {
		v, ok := g[k]
		if !ok {
			return nil, true
		}
		raw, ok := v.(string)
		if !ok || len(raw) > 4096 {
			return nil, false
		}
		if raw == "" {
			return nil, true
		}
		var out []*regexp.Regexp
		for _, pattern := range strings.Split(raw, string(rune(96))) {
			r, e := regexp.Compile(pattern)
			if e != nil {
				return nil, false
			}
			out = append(out, r)
		}
		return out, true
	}
	incl, ok := compile("filter")
	if !ok {
		return nil, false
	}
	excl, ok := compile("exclude-filter")
	if !ok {
		return nil, false
	}
	return func(s string) bool {
		for _, r := range excl {
			if r.MatchString(s) {
				return false
			}
		}
		for _, r := range incl {
			if r.MatchString(s) {
				return true
			}
		}
		return len(incl) == 0
	}, true
}
