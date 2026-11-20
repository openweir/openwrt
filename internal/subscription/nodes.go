package subscription

import (
	"errors"

	"github.com/openweir/openwrt/internal/proxyspec"
)

var errNode = errors.New("invalid_node")
var errOption = proxyspec.ErrOption
var errSnellCredential = errors.New("nonstandard_snell_credential")
var errInvalidCredential = errors.New("invalid_credential")

func first(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
func proxyProtocol(m map[string]any) string {
	kind := field(m, "type")
	switch kind {
	case "ss":
		return "shadowsocks"
	case "ssr":
		return "shadowsocksr"
	case "http":
		if m["tls"] == true {
			return "https"
		}
	}
	return kind
}
