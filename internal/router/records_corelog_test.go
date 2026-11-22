package router

import (
	"fmt"
	"strings"
	"testing"
)

// Lines a core started with a template-routed profile wrote (China shortcut on, fake-ip DNS,
// http:// test address that closes the connection after one answer), and the forms mihomo
// writes for providers and rule sets. "" means the line is dropped.
func TestCoreLogClassifiesMihomoLines(t *testing.T) {
	const at = `time="2026-11-22T09:51:42.596400247-08:00" `
	for _, c := range []struct{ line, reason, detail string }{
		// The classical sets the fake-ip filter lists on purpose, at every load.
		{at + `level=warning msg="Disney Plus provider is Classical, only matching domain rules in fake-ip-filter"`, "", ""},
		{at + `level=warning msg="YouTube (classical) provider is Classical, only matching domain rules in fake-ip-filter"`, "", ""},
		{at + `level=warning msg="规则 provider is Classical, only matching it contain domain rule"`, "", ""},
		{at + `level=warning msg="Steam provider is Classical, only matching it contain ip rule"`, "", ""},
		// A node that passed its first test request, and the advice paired with it, which says
		// "proxy providers" without one failing.
		{at + `level=error msg="node:7a52b59ae9ef9f8a902b78b674dde5eb failed to get the second response from http://127.0.0.1:28204/generate_204: Head \"http://127.0.0.1:28204/generate_204\": read tcp 127.0.0.1:36064->127.0.0.1:28290: use of closed network connection"`, "", ""},
		{at + `level=error msg="node:1fae3fcd39769a54d040013102625210 failed to get the second response from http://127.0.0.1:28204/generate_204: Head \"http://127.0.0.1:28204/generate_204\": EOF"`, "", ""},
		{at + `level=warning msg="It is recommended to use HTTPS for provider.health-check.url and group.url to ensure better reliability. Due to some proxy providers hijacking test addresses and not being compatible with repeated HEAD requests, using HTTP may result in failed tests."`, "", ""},
		{at + `level=warning msg="Mihomo shutting down"`, "", ""},
		// Providers and rule sets, by the forms mihomo writes, ahead of the error words.
		{at + `level=error msg="initial proxy provider airport error: open ./providers/airport.yaml: no such file or directory"`, "node_provider_issue", ""},
		{at + `level=error msg="initial rule provider Netflix error: open ./rulesets/0e167bcf6e445d42194a8ef64a0187c8a0581c1608071fbb351788bf2a81bf3d.mrs: no such file or directory"`, "rule_provider_issue", ""},
		{at + `level=error msg="initial rule provider geosite-cn error: invalid mrs file"`, "rule_provider_issue", ""},
		{at + `level=error msg="[Provider] Netflix pull error: dial tcp 203.0.113.9:443: connect: connection refused"`, "rule_provider_issue", ""},
		{at + `level=warning msg="parse classical rule [PROCESS-NAME,steam.exe] error: unsupported rule type on classical rule-set: PROCESS-NAME"`, "rule_provider_issue", ""},
		{at + `level=warning msg="skip invalid domain from rule provider: invalid domain \"a/b\""`, "rule_provider_issue", ""},
		// Anything else keeps a redacted detail.
		{at + `level=warning msg="[CacheFile] write cache to /etc/openweir/core/cache.db failed: timeout"`, "core_diagnostic", "cachefile write cache to /etc/openweir/... failed: timeout"},
		{at + `level=warning msg="[Rule] rematch proxy group:af60f450c0dd13e8eab38ef9bfaed433 failed to update metadata: 🇭🇰 香港 01 sub.example.com 10.0.0.1:53"`, "core_diagnostic", "rule rematch proxy <group> failed to update metadata: 01 <host> <addr>"},
		{`ERROR panic: runtime error: index out of range [3] with length 3`, "core_diagnostic", "panic: runtime error: index out of range 3 with length 3"},
	} {
		r := NewRecords()
		s := logSink{r: r}
		_, _ = s.Write([]byte(c.line + "\n"))
		logs := r.Logs(0, 10, "", "", "")
		if c.reason == "" {
			if len(logs) != 0 {
				t.Errorf("%s\n logged %+v", c.line, logs)
			}
			continue
		}
		if len(logs) != 1 || logs[0].Message != c.reason || logs[0].Detail != c.detail {
			t.Errorf("%s\n got %+v\nwant %s %q", c.line, logs, c.reason, c.detail)
		}
	}
}

func TestCoreDetailRedacts(t *testing.T) {
	for in, want := range map[string]string{
		// Links lose all but their scheme: credentials, host, path, query and signature.
		`level=error msg="download failed: get \"https://user:secret@sub.example.com/link?token=9f8e7d6c5b4a\": unexpected status 403"`: "download failed: get https://<url> : unexpected status 403",
		// Two-label names, user@ prefixes, IPv6 and IPv4 addresses with ports.
		`level=warning msg="sync with admin@example.com via [2001:db8::1]:443 and 192.0.2.1:53 failed"`: "sync with <host> via <addr> and <addr> failed",
		// Node IDs, deep paths and long tokens with digits; plain words of any length stay.
		`level=warning msg="node:0123456789abcdef0123456789abcdef read /usr/share/openweir/rules/x.mrs key 6b1f0e9a2c4d8e7f6a5b4c3d2e1f0a9b global-client-fingerprint"`: "<node> read /usr/share/... key <id> global-client-fingerprint",
		// Nothing but plain ASCII: a name in Chinese or with emoji is left out, its plain words stay.
		`level=warning msg="🇯🇵 日本 provider failed"`: "provider failed",
		`warn[0000] something odd happened`:         "something odd happened",
	} {
		if got := coreDetail(strings.ToLower(in)); got != want {
			t.Errorf("%s\n got %q\nwant %q", in, got, want)
		}
	}
	long := coreDetail(`level=warning msg="` + strings.Repeat("word ", 60) + `"`)
	if len(long) > 120 || !strings.HasPrefix(long, "word word") || strings.HasSuffix(long, " ") {
		t.Errorf("not capped: %q", long)
	}
}

// One cause reported with a different detail each time keeps a few entries, then folds into
// one without a detail; repeats of one detail fold as before.
func TestCoreLogFoldsVaryingDetails(t *testing.T) {
	r := NewRecords()
	s := logSink{r: r}
	for i := range 20 {
		_, _ = fmt.Fprintf(&s, "level=warning msg=\"[CacheFile] skip storage for key k%d: payload exceeds %d bytes\"\n", i, 1000+i)
	}
	for range 3 {
		_, _ = s.Write([]byte(`level=warning msg="[CacheFile] skip storage for key k0: payload exceeds 1000 bytes"` + "\n"))
	}
	logs := r.Logs(0, 100, "", "", "")
	total, plain := 0, 0
	for _, e := range logs {
		if e.Message != "core_diagnostic" {
			t.Fatal(e)
		}
		total += max(e.Count, 1)
		if e.Detail == "" {
			plain++
		}
	}
	if len(logs) != detailVariants+1 || plain != 1 || total != 23 {
		t.Fatalf("%d entries, %d without a detail, %d counted: %+v", len(logs), plain, total, logs)
	}
	if e := logs[0]; e.Detail != "cachefile skip storage for key k0: payload exceeds 1000 bytes" || e.Count != 4 {
		t.Fatalf("repeats of one detail did not fold: %+v", e)
	}
}
