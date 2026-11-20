package proxyspec

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

var errNode = errors.New("invalid_node")
var errOption = ErrOption
var errSnellCredential = errors.New("nonstandard_snell_credential")
var errInvalidCredential = errors.New("invalid_credential")

func field(m map[string]any, key string) string { return str(m, key) }
func integer(v any) (int, bool) {
	s := fmt.Sprint(v)
	n, err := strconv.Atoi(s)
	return n, err == nil
}
func hostValid(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if strings.HasSuffix(s, ".") {
		s = strings.TrimSuffix(s, ".")
	}
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
