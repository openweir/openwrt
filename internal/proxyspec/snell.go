package proxyspec

func normalizeSnell(m map[string]any) error {
	version, ok := integer(m["version"])
	if !ok {
		return errNode
	}
	if v := field(m, "psk"); v == "" || version == 6 && (len(v) < 12 || len(v) > 255) {
		return errInvalidCredential
	}
	switch version {
	case 4, 5:
		if m["mode"] != nil || m["userkey"] != nil {
			return errOption
		}
		switch field(m, "obfs_mode") {
		case "", "none", "http", "tls":
		default:
			return errOption
		}
		m["version"] = version
	case 6:
		m["version"] = version
		if m["obfs_mode"] != nil || m["obfs_host"] != nil {
			return errOption
		}
		switch field(m, "mode") {
		case "", "default", "unshaped", "unsafe-raw":
		default:
			return errOption
		}
	default:
		return errOption
	}
	if key, exists := m["userkey"]; exists {
		if _, ok := key.(string); !ok {
			return errInvalidCredential
		}
	}
	for _, k := range []string{"mode", "obfs_mode", "obfs_host"} {
		if v, exists := m[k]; exists {
			if _, ok := v.(string); !ok {
				return errNode
			}
		}
	}
	if v := m["reuse"]; v != nil {
		if _, ok := v.(bool); !ok {
			return errNode
		}
	}
	return nil
}
