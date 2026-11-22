package subscription

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openweir/subconv"
	"github.com/openweir/subconv/rules"
)

// The suite stays off the network: only the tests that serve a rules branch use one.
func TestMain(m *testing.M) {
	TemplateHosts = nil
	os.Exit(m.Run())
}

// A routing template as the rules branch serves it: emoji group names and a rule set on the branch.
const branchTemplate = `proxy-groups:
  - name: "🚀 Proxy"
    type: select
    proxies: [♻️ Auto, DIRECT]
    include-all: true
    exclude-filter: (?i)expire|剩余
  - name: ♻️ Auto
    type: url-test
    include-all: true
    exclude-filter: (?i)expire|剩余
    url: https://www.gstatic.com/generate_204
    interval: 300
  - name: "🎯 Domestic"
    type: select
    proxies: [DIRECT, "🚀 Proxy"]
rule-providers:
  LAN:
    type: http
    behavior: classical
    format: text
    url: "{rules}/providers/dler/lan.classical.txt"
    path: ./rules/openweir/dler/lan.classical.txt
    interval: 86400
rules:
  - RULE-SET,LAN,DIRECT
  - "GEOIP,CN,🎯 Domestic"
  - "MATCH,🚀 Proxy"
`

const branchLAN = "IP-CIDR,192.168.0.0/16,no-resolve\nDOMAIN-SUFFIX,lan\n"

// testBranch serves a rules branch: its manifest, template and one rule set.
type testBranch struct {
	srv      *httptest.Server
	version  int64
	lan      string // served in place of the manifest's rule set when set
	down     atomic.Bool
	requests atomic.Int32
}

func serveBranch(t *testing.T, version int64) *testBranch {
	t.Helper()
	b := &testBranch{version: version}
	file := func(path, kind, data string) rules.File {
		sum := sha256.Sum256([]byte(data))
		return rules.File{Path: path, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Kind: kind, Updated: "2026-11-21"}
	}
	b.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.requests.Add(1)
		if b.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/" + rules.ManifestPath:
			m, _ := json.Marshal(rules.Manifest{Version: b.version, Files: []rules.File{
				file(rules.TemplatePath, "template", branchTemplate),
				file("providers/dler/lan.classical.txt", "rule-set", branchLAN),
			}})
			w.Write(m)
		case "/" + rules.TemplatePath:
			w.Write([]byte(branchTemplate))
		case "/providers/dler/lan.classical.txt":
			w.Write([]byte(first(b.lan, branchLAN)))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(b.srv.Close)
	hosts, dir := TemplateHosts, TemplateDir
	TemplateHosts, TemplateDir = []rules.Host{{Base: b.srv.URL, Operator: "test"}}, t.TempDir()
	t.Cleanup(func() { TemplateHosts, TemplateDir = hosts, dir })
	return b
}

func (b *testBranch) fetcher() Fetcher { return Fetcher{embeddedClient: b.srv.Client()} }

const twoLinks = "ss://YWVzLTEyOC1nY206cA@hk.example.com:8388#HK%2001\nss://YWVzLTEyOC1nY206cA@info.example.com:8388#%E5%89%A9%E4%BD%99%E6%B5%81%E9%87%8F\n"

func fileSource(t *testing.T, rules string) (*Store, string) {
	t.Helper()
	store := OpenStore(t.TempDir())
	if err := store.Configure(Source{ID: "s", Name: "test", Kind: "file", Rules: rules}); err != nil {
		t.Fatal(err)
	}
	return store, "s"
}

func TestTemplateRoutesASubscriptionWithoutRules(t *testing.T) {
	b := serveBranch(t, 42)
	store, id := fileSource(t, RoutingOwn)
	c, err := b.fetcher().Refresh(t.Context(), store, id, []byte(twoLinks), Policy{})
	if err != nil || c.Decision != "ready" || c.Profile.Local {
		t.Fatal(err, c.Decision, c.Notices)
	}
	p := c.Profile
	if p.Template == nil || p.Template.Reason != subconv.TemplateNoRules || p.Template.Version != 42 || p.Template.Cached {
		t.Fatalf("%+v", p.Template)
	}
	var names []string
	for _, g := range p.Groups {
		names = append(names, g.Name)
	}
	if !slices.Equal(names, []string{"🚀 Proxy", "♻️ Auto", "🎯 Domestic"}) || len(p.Groups[1].Members) != 1 {
		t.Fatal(names, p.Groups)
	}
	if len(p.BinarySets) != 1 || p.BinarySets[0].Tag != "LAN" || string(p.BinarySets[0].Data) != branchLAN || p.BinarySets[0].Behavior != "classical" {
		t.Fatalf("%+v", p.BinarySets)
	}
	if len(p.Rules) != 2 || p.Rules[0].RuleSet != "LAN" || p.Final != p.Groups[0].ID {
		t.Fatal(p.Rules, p.Final)
	}
	// The router keeps what it got on flash, under the branch's paths.
	for _, path := range []string{rules.ManifestPath, rules.TemplatePath, "providers/dler/lan.classical.txt"} {
		if _, err := os.Stat(filepath.Join(TemplateDir, path)); err != nil {
			t.Fatal(err)
		}
	}
	if st, _ := store.Status(id); st.Template == nil || st.Template.Reason != subconv.TemplateNoRules {
		t.Fatal("status lacks the template")
	}
}

const ownRules = `proxies:
  - {name: HK 01, type: ss, server: hk.example.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-groups:
  - {name: Mine, type: select, proxies: [HK 01]}
rules:
  - DOMAIN-SUFFIX,a.example,Mine
  - MATCH,Mine
`

func TestRoutingChoice(t *testing.T) {
	b := serveBranch(t, 42)
	store, id := fileSource(t, RoutingOwn)
	c, err := b.fetcher().Refresh(t.Context(), store, id, []byte(ownRules), Policy{})
	if err != nil || c.Profile.Template != nil || c.Profile.Groups[0].Name != "Mine" {
		t.Fatal("usable rules gave way to the template", err, c.Profile.Template)
	}
	template := RoutingTemplate
	if err := store.Preferences(id, Preferences{Rules: &template}); err != nil {
		t.Fatal(err)
	}
	if st, _ := store.Status(id); st.Rules != RoutingTemplate {
		t.Fatal("choice not saved")
	}
	c, err = b.fetcher().Refresh(t.Context(), store, id, []byte(ownRules), Policy{AllowLocalFallback: true})
	if err != nil || c.Decision != "ready" || c.Profile.Template == nil || c.Profile.Template.Reason != subconv.TemplateRequested || c.Profile.Groups[0].Name != "🚀 Proxy" {
		t.Fatal(err, c.Decision, c.Profile.Template, c.Notices)
	}
	// An older client leaves the choice as it was; an unknown one is refused.
	if err := store.Preferences(id, Preferences{}); err != nil {
		t.Fatal(err)
	}
	if st, _ := store.Status(id); st.Rules != RoutingTemplate {
		t.Fatal("choice lost")
	}
	bad := "sometimes"
	if err := store.Preferences(id, Preferences{Rules: &bad}); err == nil {
		t.Fatal("unknown routing choice accepted")
	}
}

func TestTemplateSurvivesHostsThatDoNotAnswer(t *testing.T) {
	b := serveBranch(t, 42)
	store, id := fileSource(t, RoutingOwn)
	if _, err := b.fetcher().Refresh(t.Context(), store, id, []byte(twoLinks), Policy{}); err != nil {
		t.Fatal(err)
	}
	b.down.Store(true)
	c, err := b.fetcher().Refresh(t.Context(), store, id, []byte(twoLinks+"ss://YWVzLTEyOC1nY206cA@jp.example.com:8388#JP%2001\n"), Policy{})
	if err != nil || c.Decision != "ready" || c.Profile.Template == nil || !c.Profile.Template.Cached || len(c.Profile.BinarySets) != 1 {
		t.Fatal(err, c.Decision, c.Profile.Template, c.Notices)
	}
}

func TestTemplateRefusesARollback(t *testing.T) {
	b := serveBranch(t, 42)
	store, id := fileSource(t, RoutingOwn)
	if _, err := b.fetcher().Refresh(t.Context(), store, id, []byte(twoLinks), Policy{}); err != nil {
		t.Fatal(err)
	}
	// A host now serving an older branch is not followed back: the router keeps its copy.
	b.version = 41
	c, err := b.fetcher().Refresh(t.Context(), store, id, []byte(twoLinks+"ss://YWVzLTEyOC1nY206cA@jp.example.com:8388#JP%2001\n"), Policy{})
	if err != nil || c.Profile.Template == nil || c.Profile.Template.Version != 42 || !c.Profile.Template.Cached {
		t.Fatal(err, c.Profile.Template)
	}
}

// A rule set unlike the manifest, or one no host serves, is not used: the subscription is
// still updated, and routes by the router's default until a later refresh gets the set.
func TestTemplateRuleSetsMustMatchTheManifest(t *testing.T) {
	b := serveBranch(t, 42)
	b.lan = "DOMAIN-SUFFIX,tampered.example\n"
	store, id := fileSource(t, RoutingOwn)
	c, err := b.fetcher().Refresh(t.Context(), store, id, []byte(twoLinks), Policy{})
	if err != nil || c.Decision != "ready" || !c.Profile.Local || c.Profile.Template != nil || len(c.Profile.Nodes) != 2 {
		t.Fatal("a rule set unlike the manifest stopped or entered the update", err, c.Decision, c.Profile.Template)
	}
	if !slices.ContainsFunc(c.Notices, func(n Notice) bool { return n.Code == "subconv_template_unavailable" }) {
		t.Fatal(c.Notices)
	}
	if _, err := os.Stat(filepath.Join(TemplateDir, "providers/dler/lan.classical.txt")); err == nil {
		t.Fatal("tampered rule set cached")
	}
	b.lan = ""
	if c, err = b.fetcher().Refresh(t.Context(), store, id, []byte(twoLinks), Policy{AllowLocalFallback: true}); err != nil || c.Profile.Template == nil {
		t.Fatal("a later refresh did not take the template", err, c.Decision)
	}
}

const lossyRejections = `proxies:
  - {name: HK 01, type: ss, server: hk.example.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-groups:
  - {name: Mine, type: select, proxies: [HK 01]}
rules:
  - USER-AGENT,ads*,REJECT
  - DOMAIN-SUFFIX,a.example,Mine
  - MATCH,Mine
`

// Rules the template replaced no longer weigh: an automatic update does not stop for the
// rejection a subscription always loses.
func TestTemplateUpdatesNeedNoConfirmation(t *testing.T) {
	b := serveBranch(t, 42)
	store, id := fileSource(t, RoutingOwn)
	for range 2 {
		c, err := b.fetcher().Refresh(t.Context(), store, id, []byte(lossyRejections), Policy{Scheduled: true})
		if err != nil || c.Decision != "ready" || c.Profile.Template == nil || c.Profile.Template.Reason != subconv.TemplateDropped {
			t.Fatal(err, c.Decision, c.Notices)
		}
		if slices.ContainsFunc(c.Notices, func(n Notice) bool { return n.Dangerous || n.Code == "subconv_unsupported_rule" }) {
			t.Fatal(c.Notices)
		}
	}
}

// A subscription on a geodata mirror the router does not trust: subconv keeps its GEOIP and
// GEOSITE rules, and the router drops them (clashDefaultGeo).
const mirrorGeo = `geox-url:
  geoip: https://cdn.jsdmirror.com/gh/MetaCubeX/meta-rules-dat@release/geoip.dat
  geosite: https://cdn.jsdmirror.com/gh/MetaCubeX/meta-rules-dat@release/geosite.dat
  mmdb: https://cdn.jsdmirror.com/gh/MetaCubeX/meta-rules-dat@release/country.mmdb
proxies:
  - {name: HK 01, type: ss, server: hk.example.com, port: 8388, cipher: aes-128-gcm, password: p}
  - {name: HK 02, type: ss, server: hk2.example.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-groups:
  - {name: Proxy, type: select, proxies: [HK 01, HK 02]}
rules:
`

func mirrorRules(rules ...string) string {
	return mirrorGeo + "  - " + strings.Join(rules, "\n  - ") + "\n"
}

// The rules the router drops itself count with subconv's toward the template: the same tenth,
// and the final rule.
func TestRouterDropsCountTowardTheTemplate(t *testing.T) {
	domains := func(n int) []string {
		var out []string
		for i := range n {
			out = append(out, fmt.Sprintf("DOMAIN-SUFFIX,d%d.example,Proxy", i))
		}
		return out
	}
	long := strings.Repeat("L", 400)
	for _, tc := range []struct {
		name, body      string
		reason          string
		dropped, total  int
		ownRules, notes int // with the subscription's own rules: those kept, and the router's notices
	}{
		{name: "custom geodata", reason: subconv.TemplateDropped, dropped: 4, total: 6,
			body: mirrorRules("GEOSITE,google,Proxy", "GEOSITE,youtube,Proxy", "GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT", "DOMAIN-SUFFIX,a.example,Proxy", "MATCH,Proxy")},
		{name: "a tenth", ownRules: 8, notes: 1,
			body: mirrorRules(slices.Concat([]string{"GEOSITE,google,Proxy"}, domains(8), []string{"MATCH,Proxy"})...)},
		// subconv drops the USER-AGENT rule, too few by itself, and the router one more.
		{name: "with subconv's", reason: subconv.TemplateDropped, dropped: 2, total: 11,
			body: mirrorRules(slices.Concat([]string{"USER-AGENT,ads*,REJECT", "GEOSITE,google,Proxy"}, domains(8), []string{"MATCH,Proxy"})...)},
		{name: "missing rule set", reason: subconv.TemplateDropped, dropped: 1, total: 3,
			body: "rule-providers:\n  ads: {type: file, behavior: domain, path: ./ads.yaml}\n" + mirrorRules("RULE-SET,ads,REJECT", "DOMAIN-SUFFIX,a.example,Proxy", "MATCH,Proxy")},
		// A group name too long for the router: its group and the final rule to it go.
		{name: "final rule", reason: subconv.TemplateNoMatch,
			body: strings.Replace(mirrorRules("DOMAIN-SUFFIX,a.example,Proxy", "MATCH,"+long), "rules:", "  - {name: "+long+", type: select, proxies: [HK 01]}\nrules:", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := serveBranch(t, 42)
			store, id := fileSource(t, RoutingOwn)
			f := b.fetcher()
			f.ruleImportRoot = t.TempDir()
			c, err := f.Refresh(t.Context(), store, id, []byte(tc.body), Policy{Scheduled: true})
			if err != nil || c.Decision != "ready" {
				t.Fatal(err, c.Decision, c.Notices)
			}
			p := c.Profile
			if tc.reason == "" {
				if p.Template != nil || p.Groups[0].Name != "Proxy" || len(p.Rules) != tc.ownRules || p.Final == "" || len(c.Notices) != tc.notes {
					t.Fatal("the subscription's own rules gave way", p.Template, p.Rules, c.Notices)
				}
				return
			}
			want := TemplateUse{Version: 42, Reason: tc.reason, Dropped: tc.dropped, Total: tc.total}
			if p.Template == nil || *p.Template != want || p.Groups[0].Name != "🚀 Proxy" || p.Local {
				t.Fatalf("%+v %v", p.Template, c.Notices)
			}
			// The rules the template replaced no longer weigh.
			if slices.ContainsFunc(c.Notices, func(n Notice) bool { return n.Dangerous || partialNotices[n.Code] }) {
				t.Fatal(c.Notices)
			}
			if st, _ := store.Status(id); st.Template == nil || *st.Template != want {
				t.Fatalf("status: %+v", st.Template)
			}
		})
	}
}

// A subscription asks for the template or keeps its own rules, whatever the router drops: with
// the template chosen, the reason stays the choice, and without a rules branch, subconv never
// takes the template.
func TestRouterDropsLeaveFixedRoutingAlone(t *testing.T) {
	body := mirrorRules("GEOSITE,google,Proxy", "GEOSITE,youtube,Proxy", "GEOSITE,cn,DIRECT", "GEOIP,CN,DIRECT", "DOMAIN-SUFFIX,a.example,Proxy", "MATCH,Proxy")
	store, id := fileSource(t, RoutingOwn)
	c, err := (Fetcher{}).Refresh(t.Context(), store, id, []byte(body), Policy{})
	if err != nil || c.Decision != "ready" || c.Profile.Template != nil || len(c.Profile.Rules) != 1 || c.Profile.Final == "" {
		t.Fatal(err, c.Decision, c.Profile.Template, c.Profile.Rules)
	}
	b := serveBranch(t, 42)
	store, id = fileSource(t, RoutingTemplate)
	c, err = b.fetcher().Refresh(t.Context(), store, id, []byte(body), Policy{})
	if err != nil || c.Decision != "ready" || c.Profile.Template == nil || *c.Profile.Template != (TemplateUse{Version: 42, Reason: subconv.TemplateRequested}) {
		t.Fatal(err, c.Decision, c.Profile.Template)
	}
}

// A rule the router drops is dangerous as one subconv drops: when it rejected traffic.
func TestRejectedRulesAreWeighedByTheirTarget(t *testing.T) {
	for rule, want := range map[string]bool{
		"GEOSITE,category-ads-all,REJECT":              true,
		"GEOIP,AD,REJECT-DROP,no-resolve":              true,
		"IP-CIDR,10.0.0.0/8,reject-200,no-resolve,src": true,
		"DOMAIN-SUFFIX,reject.example,Proxy":           false,
		"RULE-SET,reject,DIRECT":                       false,
	} {
		if rejects(rule) != want || dropsRejection(rule+": rule type") != want {
			t.Error(rule)
		}
	}
	// Custom geodata, and a rule type the router does not compile.
	p := mustParse(t, mirrorRules("GEOSITE,category-ads-all,REJECT", "GEOSITE,reject-list,Proxy", "PROCESS-NAME,ads,REJECT", "PROCESS-NAME,reject-helper,DIRECT", "MATCH,Proxy"))
	var got []string
	for _, n := range p.Notices {
		got = append(got, fmt.Sprint(n.Code, " ", n.At, " ", n.Dangerous))
	}
	if !slices.Equal(got, []string{"rule_provider_custom_geo GEOSITE category-ads-all true", "rule_provider_custom_geo GEOSITE reject-list false", "mihomo_unsupported_rule rule 3 true", "mihomo_unsupported_rule rule 4 false"}) {
		t.Fatal(got)
	}
}

// The template's rules mean the default geodata, whatever the subscription chose for its own,
// and a script the subscription routed by is gone with its rules.
func TestTemplateIgnoresTheSubscriptionsGeodataAndScript(t *testing.T) {
	b := serveBranch(t, 42)
	store, id := fileSource(t, RoutingTemplate)
	body := "geox-url:\n  geoip: https://example.org/my/geoip.dat\nscript:\n  code: |\n    def main(ctx, m): return 'DIRECT'\n" + ownRules
	c, err := b.fetcher().Refresh(t.Context(), store, id, []byte(body), Policy{})
	if err != nil || c.Decision != "ready" || c.Profile.Template == nil {
		t.Fatal(err, c.Decision, c.Notices)
	}
	if !slices.ContainsFunc(c.Profile.Rules, func(r Rule) bool { return r.RuleSet == DomesticIPSet }) {
		t.Fatal("the template's GEOIP,CN rule was dropped", c.Profile.Rules)
	}
	if slices.ContainsFunc(c.Notices, func(n Notice) bool { return n.Code == "script" || n.Code == "rule_provider_custom_geo" }) {
		t.Fatal(c.Notices)
	}
}

// Seventy rule sets arrive six at a time.
func TestTemplateSetsDownloadInParallel(t *testing.T) {
	var active, peak atomic.Int32
	files := []rules.File{}
	providers := map[string]any{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+rules.ManifestPath {
			m, _ := json.Marshal(rules.Manifest{Version: 7, Files: files})
			w.Write(m)
			return
		}
		n := active.Add(1)
		defer active.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(20 * time.Millisecond)
		w.Write([]byte("DOMAIN," + strings.TrimPrefix(r.URL.Path, "/") + "\n"))
	}))
	defer srv.Close()
	files = append(files, rules.File{Path: rules.TemplatePath, Size: 1, SHA256: strings.Repeat("0", 64)})
	for i := range 70 {
		path := fmt.Sprintf("providers/set%d.txt", i)
		data := "DOMAIN," + path + "\n"
		sum := sha256.Sum256([]byte(data))
		files = append(files, rules.File{Path: path, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
		providers[fmt.Sprintf("s%d", i)] = map[string]any{"type": "http", "url": srv.URL + "/" + path}
	}
	client := &rules.Client{HTTP: srv.Client(), Hosts: []rules.Host{{Base: srv.URL, Operator: "test"}}, Cache: templateCache{dir: t.TempDir()}}
	sets, err := fetchTemplateSets(t.Context(), client, 7, providers)
	if err != nil || len(sets) != 70 || string(sets["s3"]) != "DOMAIN,providers/set3.txt\n" {
		t.Fatal(err, len(sets))
	}
	if p := peak.Load(); p < 2 || p > templateParallel {
		t.Fatal("concurrent downloads:", p)
	}
}

func TestWithoutTemplateTheRouterRoutesByDefault(t *testing.T) {
	b := serveBranch(t, 42)
	b.down.Store(true)
	store, id := fileSource(t, RoutingTemplate)
	c, err := b.fetcher().Refresh(t.Context(), store, id, []byte(ownRules), Policy{})
	if err != nil || c.Decision != "ready" || !c.Profile.Local || c.Profile.Template != nil || len(c.Profile.Groups) != 0 {
		t.Fatal(err, c.Decision, c.Notices)
	}
	if !slices.ContainsFunc(c.Notices, func(n Notice) bool { return n.Code == "subconv_template_unavailable" && !strings.Contains(n.At, "://") }) {
		t.Fatal(c.Notices)
	}
}

func TestBuildLeavesTheConfigToTheRouter(t *testing.T) {
	b := serveBranch(t, 42)
	branch, done := b.fetcher().branch()
	defer done()
	c, err := convert(t.Context(), []byte(ownRules), RoutingTemplate, branch)
	if err != nil || c.template == nil {
		t.Fatal(err, c.notices)
	}
	for key := range c.doc {
		if !slices.Contains([]string{"proxies", "proxy-groups", "rule-providers", "rules"}, key) {
			t.Fatal("subconv wrote config the router writes itself:", key)
		}
	}
}

// The rules branch is reached as a provider is: a host on a private address is refused.
func TestBranchKeepsTheProviderPolicy(t *testing.T) {
	b := serveBranch(t, 42)
	store, id := fileSource(t, RoutingOwn)
	c, err := (Fetcher{}).Refresh(t.Context(), store, id, []byte(twoLinks), Policy{})
	if err != nil || c.Profile.Template != nil || b.requests.Load() != 0 {
		t.Fatal("reached a branch on loopback", err, b.requests.Load())
	}
}

func TestTemplateCacheWritesOnlyChanges(t *testing.T) {
	c := templateCache{dir: t.TempDir()}
	c.Put("providers/a.txt", []byte("one"))
	path := filepath.Join(c.dir, "providers", "a.txt")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	c.Put("providers/a.txt", []byte("one"))
	if st, _ := os.Stat(path); !st.ModTime().Equal(old) {
		t.Fatal("unchanged value rewritten")
	}
	c.Put("providers/a.txt", []byte("two"))
	if b, ok := c.Get("providers/a.txt"); !ok || string(b) != "two" {
		t.Fatal("changed value not kept")
	}
	c.Put("../escape", []byte("x"))
	if _, ok := c.Get("../escape"); ok {
		t.Fatal("cache left its directory")
	}
	if entries, _ := os.ReadDir(filepath.Join(c.dir, "providers")); len(entries) != 1 {
		t.Fatal("temporary file left behind", entries)
	}
}

func TestSelectionsOfRemovedGroupsReset(t *testing.T) {
	prev := mustParse(t, ownRules)
	next := mustParse(t, strings.ReplaceAll(ownRules, "Mine", "Other"))
	gone, node := prev.Groups[0].ID, prev.Nodes[0].ID
	if c := Assess(next, &prev, Policy{Choices: map[string]string{gone: node}}); c.Decision != "ready" {
		t.Fatal("a selection of a removed group blocked the update", c.Decision)
	}
	kept := next.Groups[0].ID
	if c := Assess(next, &prev, Policy{Choices: map[string]string{kept: "node:" + strings.Repeat("0", 32)}}); c.Decision != "blocked" {
		t.Fatal("a selection in a kept group lost its member silently", c.Decision)
	}
}

// Every notice the router reports has a text in LuCI.
func TestTemplateNoticesHaveTexts(t *testing.T) {
	js, err := os.ReadFile("../../files/www/luci-static/resources/openweir/pages/sources.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"subconv_template_unavailable", "provider_option_ignored", "dialer_proxy_unavailable"} {
		if !strings.Contains(string(js), "\n    "+code+": ") {
			t.Error("no text for", code)
		}
	}
	for _, reason := range []string{subconv.TemplateRequested, subconv.TemplateNoRules, subconv.TemplateNoMatch, subconv.TemplateDropped} {
		if !strings.Contains(string(js), reason+": ") {
			t.Error("no text for template reason", reason)
		}
	}
}
