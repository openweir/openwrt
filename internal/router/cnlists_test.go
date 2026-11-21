package router

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
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

func TestChinaListMoveDuringStartReloadsOnceRunning(t *testing.T) {
	var starts, reloads atomic.Int32
	proceed := make(chan struct{})
	f := reloadService{fakeService{start: func(c context.Context, _ Intent) error {
		starts.Add(1)
		select {
		case <-proceed:
			return nil
		case <-c.Done():
			return c.Err()
		}
	}}, func(context.Context, Intent) error { reloads.Add(1); return nil }}
	i := initial()
	i.Enabled = true
	i.Source = "primary"
	m := New(&fakeStore{i: i}, f, Timing{time.Second, 100 * time.Millisecond, 5 * time.Millisecond, time.Second})
	ctx, end := context.WithCancel(context.Background())
	defer end()
	go m.Run(ctx)
	eventually(t, func() bool { return starts.Load() == 1 && m.Status().Phase == "starting" })
	m.Reapply()
	close(proceed)
	eventually(t, func() bool { return reloads.Load() == 1 && m.Status().Phase == "running" })
	if starts.Load() != 1 {
		t.Fatal("a list move restarted the core")
	}
}
