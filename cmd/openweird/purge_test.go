package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openweir/openwrt/internal/router"
)

func TestPurgeDeletesWhatOpenWeirKeeps(t *testing.T) {
	paths := purgePaths()
	for _, want := range []string{
		"/etc/openweir/kernel", "/etc/openweir/mihomo-kernel", "/tmp/openweir/kernel", "/tmp/openweir/mihomo-kernel",
		"/etc/openweir/sources", "/etc/openweir/private", "/etc/openweir/rulesets", "/etc/openweir/cnlists",
		// The routing template cache, geodata (up to 64 MiB a file) and the user's imported files.
		"/etc/openweir/template", "/etc/openweir/geodata", "/etc/openweir/imports",
	} {
		if !slices.Contains(paths, want) {
			t.Error("purge keeps", want)
		}
	}
	// Each path is removed recursively: none may reach beyond OpenWeir's own directories.
	for _, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || !strings.HasPrefix(p, router.Root+"/") && !strings.HasPrefix(p, "/tmp/openweir") {
			t.Error("purge reaches", p)
		}
	}
}
