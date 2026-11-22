package router

import "testing"

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
		// Anything else is a core diagnostic.
		{at + `level=warning msg="[CacheFile] write cache to /etc/openweir/core/cache.db failed: timeout"`, "core_diagnostic", ""},
		{at + `level=warning msg="[Rule] rematch proxy group:af60f450c0dd13e8eab38ef9bfaed433 failed to update metadata: 🇭🇰 香港 01 sub.example.com 10.0.0.1:53"`, "core_diagnostic", ""},
		{`ERROR panic: runtime error: index out of range [3] with length 3`, "core_diagnostic", ""},
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
