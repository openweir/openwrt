package router

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/openweir/openwrt/internal/cnlist"
	"github.com/openweir/openwrt/internal/subscription"
	"gopkg.in/yaml.v3"
)

const coreHome = RunDir + "/mihomo"
const packagedRules = "/usr/share/openweir/rules"

func privateDir(path string, gid int) error {
	if err := os.Mkdir(path, 0750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil || !st.IsDir() || int(st.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return errors.New("unsafe core work directory")
	}
	if err = os.Chown(path, -1, gid); err != nil {
		return err
	}
	return os.Chmod(path, 0750)
}

func prepareMihomo(p subscription.Profile, uid, gid int) error {
	if err := privateDir(coreHome, gid); err != nil {
		return err
	}
	if err := privateDir(coreHome+"/devices", gid); err != nil {
		return err
	}
	for name, target := range map[string]string{
		"rulesets": Root + "/rulesets", "builtin": packagedRules, "cnlists": cnlist.Dir,
		"GeoSite.dat": Root + "/geodata/GeoSite.dat", "GeoIP.dat": Root + "/geodata/GeoIP.dat", "country.mmdb": Root + "/geodata/country.mmdb", "ASN.mmdb": Root + "/geodata/ASN.mmdb",
	} {
		path := filepath.Join(coreHome, name)
		if err := os.Symlink(target, path); err != nil {
			if actual, e := os.Readlink(path); e != nil || actual != target {
				return errors.New("unexpected path in core home")
			}
		}
	}
	// The core may update its Bolt database, but cannot replace the provider
	// directory, the geodata links or the database file itself.
	f, err := os.OpenFile(coreHome+"/cache.db", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	err = f.Chown(uid, gid)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return subscription.MaterializeSets(p, Root+"/rulesets", gid)
}

func prepareGeo(ctx context.Context, config []byte, p subscription.Profile) error {
	var cfg struct {
		Providers map[string]obj `yaml:"rule-providers"`
		Rules     []string       `yaml:"rules"`
	}
	if err := yaml.Unmarshal(config, &cfg); err != nil {
		return err
	}
	active := p
	active.BinarySets = nil
	for _, set := range p.BinarySets {
		if _, ok := cfg.Providers[set.Tag]; ok {
			active.BinarySets = append(active.BinarySets, set)
		}
	}
	cfg.Rules = append(cfg.Rules, subscription.GeoRules(active)...)
	return subscription.PrepareGeodata(ctx, cfg.Rules, Root+"/geodata", packagedRules+"/GEODATA")
}

func macProviderName(mac string) string { return "openweir-device-" + strings.ReplaceAll(mac, ":", "") }
func policyMACs(i Intent) []string {
	var macs []string
	for _, dev := range i.Policy.Devices {
		if i.Mode == "global" && dev.Target != subscription.Direct {
			continue
		}
		match, _ := deviceMatch(dev.Address)
		if mac := stringOption(match, "source_mac_address"); mac != "" && !slices.Contains(macs, mac) {
			macs = append(macs, mac)
		}
	}
	return macs
}

// A candidate preflight only needs readable provider files. The running core's
// watcher owns updates so a concurrent check cannot consume a DHCP change.
func ensureDeviceFiles(dir string, macs []string, gid int) error {
	for _, mac := range macs {
		file := filepath.Join(dir, macProviderName(mac)+".txt")
		if _, err := os.Stat(file); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		// Link a fully initialized empty file without replacing a concurrent update.
		tmp, err := os.CreateTemp(dir, ".empty-")
		if err != nil {
			return err
		}
		err = tmp.Chown(-1, gid)
		if err == nil {
			err = tmp.Chmod(0640)
		}
		if closeErr := tmp.Close(); err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Link(tmp.Name(), file)
			if errors.Is(err, os.ErrExist) {
				err = nil
			}
		}
		os.Remove(tmp.Name())
		if err != nil {
			return err
		}
	}
	return nil
}

func syncDevices(ctx context.Context, macs []string, n Network, gid int) ([]string, error) {
	if len(macs) == 0 {
		return nil, nil
	}
	inventory, err := devicesOnNetwork(ctx, n)
	if err != nil {
		return nil, err
	}
	byMAC := map[string][]string{}
	for _, d := range inventory {
		byMAC[d.MAC] = d.Addresses
	}
	var changed []string
	for _, mac := range macs {
		var data strings.Builder
		for _, raw := range byMAC[mac] {
			if ip, e := netip.ParseAddr(raw); e == nil {
				data.WriteString(netip.PrefixFrom(ip, ip.BitLen()).String() + "\n")
			}
		}
		name := macProviderName(mac)
		file := filepath.Join(coreHome, "devices", name+".txt")
		var content = []byte(data.String())
		if old, e := os.ReadFile(file); e == nil && bytes.Equal(old, content) {
			continue
		}
		// Set ownership before rename, so the core never observes an unreadable file.
		if err := writeDeviceProvider(file, content, gid); err != nil {
			return nil, err
		}
		changed = append(changed, name)
	}
	return changed, nil
}

func writeDeviceProvider(path string, data []byte, gid int) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".device-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Chown(-1, gid)
	}
	if err == nil {
		err = f.Chmod(0640)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func (s *System) watchDevices(ctx context.Context, macs []string, n Network, gid int) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	pending := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		changed, err := syncDevices(ctx, macs, n, gid)
		if err != nil {
			continue
		}
		for _, name := range changed {
			pending[name] = true
		}
		for name := range pending {
			if err := s.Client().RefreshRules(ctx, name); err == nil {
				delete(pending, name)
			}
		}
	}
}
