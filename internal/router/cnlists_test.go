package router

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openweir/openwrt/internal/cnlist"
)

func TestChinaListProvidersFollowTheDownload(t *testing.T) {
	savedDir, savedPackaged := cnlist.Dir, cnlist.Packaged
	t.Cleanup(func() { cnlist.Dir, cnlist.Packaged = savedDir, savedPackaged })
	cnlist.Dir, cnlist.Packaged = t.TempDir(), t.TempDir()
	p := baseProfile(t, "p")
	i := initial()
	i.Source = p.Source
	n := Network{Method: "tproxy", Resolver: "192.0.2.53"}
	paths := func() map[string]string {
		out := map[string]string{}
		for name, v := range configForTest(t, i, p, n)["rule-providers"].(map[string]any) {
			if path, ok := v.(map[string]any)["path"].(string); ok {
				out[name] = path
			}
		}
		return out
	}
	want := map[string]string{"geosite-cn": "./builtin/geosite-cn.mrs", "geoip-cn": "./builtin/geoip-cn.mrs", dnsDomesticSet: "./builtin/geosite-cn.mrs", domesticIPSet: "./builtin/geoip-cn.mrs"}
	if got := paths(); len(got) != len(want) || got["geosite-cn"] != want["geosite-cn"] || got["geoip-cn"] != want["geoip-cn"] || got[dnsDomesticSet] != want[dnsDomesticSet] || got[domesticIPSet] != want[domesticIPSet] {
		t.Fatal("no download reads the packaged lists", got)
	}
	data, err := os.ReadFile("../../files/usr/share/openweir/rules/geoip-cn.mrs")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(cnlist.Dir, "geoip-cn.mrs"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := paths(); got["geoip-cn"] != "./cnlists/geoip-cn.mrs" || got[domesticIPSet] != "./cnlists/geoip-cn.mrs" || got["geosite-cn"] != want["geosite-cn"] || got[dnsDomesticSet] != want[dnsDomesticSet] {
		t.Fatal("a valid download replaces only its own list", got)
	}
	// A plugin update that ships a newer list wins over an older download.
	old := time.Now().Add(-time.Hour)
	os.Chtimes(filepath.Join(cnlist.Dir, "geoip-cn.mrs"), old, old)
	if err = os.WriteFile(filepath.Join(cnlist.Packaged, "geoip-cn.mrs"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := chinaList(cnlist.Addresses); got != "./builtin/geoip-cn.mrs" {
		t.Fatal("a newer packaged list wins", got)
	}
}
