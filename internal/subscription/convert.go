package subscription

import (
	"strings"

	"github.com/openweir/subconv"
)

// foreignFormat converts sing-box JSON and share links to OpenWeir mihomo YAML with the shared
// converter, so every source reaches the Clash path. Clash YAML and Surge/Quantumult X line
// configs pass through. format names the original format and is empty when nothing changed.
func foreignFormat(body []byte) (out []byte, format string, notices []Notice, err error) {
	s := strings.TrimSpace(strings.TrimPrefix(string(body), "\uFEFF"))
	if hasLineConfig(s) || hasYAMLRoot(s) {
		return body, "", nil, nil
	}
	kind, err := subconv.Detect(body)
	if err != nil {
		if b, ok := decoded(s); ok && !hasLineConfig(string(b)) {
			kind, err = subconv.Detect(b)
		}
		if err != nil {
			return body, "", nil, nil
		}
	}
	if kind == subconv.FormatClash {
		return body, "", nil, nil
	}
	result, err := subconv.Convert(body)
	if err != nil {
		return nil, "", nil, err
	}
	for _, w := range result.Warnings {
		// A dropped rule or rule set changes where traffic goes, so the user confirms it.
		dangerous := w.Code == subconv.WarnUnsupportedRule || w.Code == subconv.WarnUnsupportedRuleSet
		notices = append(notices, Notice{Code: "subconv_" + w.Code, At: publicLabel(w.Detail, ""), Dangerous: dangerous})
	}
	if len(result.Proxies) == 0 {
		return nil, "", notices, errNoUsableNodes
	}
	out, err = result.YAML()
	if err != nil {
		return nil, "", notices, err
	}
	format = string(kind)
	if kind == subconv.FormatLinks {
		format = "uri"
	}
	return out, format, notices, nil
}
