package subscription

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	maxClashSetEntries    = 250000
	maxSetMaterialization = 32 << 20
	maxClashRuleLine      = 8192
)

var errRulePayload = errors.New("invalid_rule_provider")

// Decode normal small YAML documents, including flow sequences, with a full
// parser. For large lists consume scalars directly: yaml.Node allocates a tree
// of hundreds of thousands of nodes before it can yield the first entry.
func readRulePayload(buf []byte, format string, add func(string) error) error {
	if len(buf) > MaxBody || !utf8.Valid(buf) {
		return errRulePayload
	}
	if format != "text" && len(buf) <= 128<<10 {
		var v struct{ Payload []string }
		d := yaml.NewDecoder(bytes.NewReader(buf))
		if err := d.Decode(&v); err != nil || v.Payload == nil || d.Decode(new(any)) != io.EOF {
			return errRulePayload
		}
		for _, line := range v.Payload {
			if err := add(line); err != nil {
				return err
			}
		}
		return nil
	}
	header := format == "text"
	ended := false
	for raw := range strings.Lines(string(buf)) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > maxClashRuleLine {
			return errRulePayload
		}
		if format != "text" {
			if !header {
				if line == "---" {
					continue
				}
				if line != "payload:" {
					return errRulePayload
				}
				header = true
				continue
			}
			if line == "..." {
				ended = true
				continue
			}
			if ended || !strings.HasPrefix(line, "- ") {
				return errRulePayload
			}
			line = strings.TrimSpace(line[2:])
			if line == "" {
				return errRulePayload
			}
			if strings.ContainsAny(line[:1], "'\"&*!|>{[") || strings.Contains(line, " #") || strings.Contains(line, ": ") {
				var scalar yaml.Node
				if yaml.Unmarshal([]byte(line), &scalar) != nil || len(scalar.Content) != 1 || scalar.Content[0].Kind != yaml.ScalarNode || scalar.Content[0].Tag != "!!str" {
					return errRulePayload
				}
				line = scalar.Content[0].Value
			}
		} else if strings.HasPrefix(line, "//") {
			continue
		}
		if err := add(line); err != nil {
			return err
		}
	}
	if !header {
		return errRulePayload
	}
	return nil
}
