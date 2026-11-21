package router

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os/user"
	"strconv"

	"github.com/openweir/openwrt/internal/control"
	"github.com/openweir/openwrt/internal/kernel"
	"github.com/openweir/openwrt/internal/subscription"
)

// ErrNeedsRestart asks the manager to fall back to a full stop and start.
var ErrNeedsRestart = errors.New("change needs a full restart")

// applied records what the running takeover was built from, so a hot reload can
// prove the firewall and listeners stay valid for the new configuration.
type applied struct {
	network, guard, telegram string
	tag                      string
	routing                  string   // what decides each connection's route; see routingKey
	config                   [32]byte // digest of the configuration the core is running
}

// routingKey covers the choices that decide where a connection goes: the mode, the
// subscription and the local rules, groups and device routes. A subscription refresh with
// the same choices keeps it, so open connections survive periodic updates. Group choices
// are applied by Select, which closes only the connections through that group.
func routingKey(i Intent) string {
	b, _ := json.Marshal(struct {
		Mode, Source  string
		DefaultDirect bool
		Groups        []LocalGroup
		Devices       []DeviceRule
		Rules         []CustomRule
		Telegram      *Telegram
	}{i.Mode, i.Source, i.Policy.DefaultDirect, i.Policy.Groups, i.Policy.Devices, i.Policy.Rules, i.Policy.Telegram})
	return string(b)
}

// networkKey covers what the network helper applied: a change needs a new takeover.
func networkKey(i Intent, n Network) string {
	return fmt.Sprint(n.Method, n.DNS, n.FakeIP, n.Family6, n.LAN, n.FailOpen, chinaShortcut(i, n))
}

func takeover(i Intent, n Network) (guard, telegram string, err error) {
	if guard, err = deviceGuardPolicy(i); err != nil {
		return
	}
	telegram, _, err = telegramAllowance(i.Policy.Telegram, n)
	return
}

func (s *System) remember(i Intent, n Network, tag string, config []byte) {
	guard, telegram, err := takeover(i, n)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.applied = nil
		return
	}
	s.applied = &applied{networkKey(i, n), guard, telegram, tag, routingKey(i), sha256.Sum256(config)}
}

// Reload swaps the core configuration in place when the listeners, firewall
// and kernel stay the same: routing mode, source, groups, rules and choices.
// Anything else returns ErrNeedsRestart.
func (s *System) Reload(ctx context.Context, i Intent) error {
	s.mu.Lock()
	last, client, running := s.applied, s.client, s.process != nil
	s.mu.Unlock()
	if last == nil || !running {
		return ErrNeedsRestart
	}
	n, e := networkOptions(ctx)
	if e != nil {
		return e
	}
	guard, telegram, e := takeover(i, n)
	if e != nil {
		return e
	}
	if networkKey(i, n) != last.network || guard != last.guard || telegram != last.telegram {
		return ErrNeedsRestart
	}
	var st kernel.Status
	var caps kernel.Capabilities
	if e = jsonCmd(ctx, &st, kernelCLI, "status"); e != nil {
		return e
	}
	if e = jsonCmd(ctx, &caps, kernelCLI, "capabilities"); e != nil {
		return e
	}
	cap, ok := caps.Targets[st.Target]
	if !ok || st.Pending || st.Selected != last.tag || caps.Tag != last.tag || caps.Repository != kernel.Repository {
		return ErrNeedsRestart
	}
	profile, e := LoadProfile(i, subscription.OpenStore(Root+"/sources"))
	if e != nil {
		return errors.New("active subscription unavailable")
	}
	account, e := user.Lookup("openweir-core")
	if e != nil {
		return errors.New("core account missing")
	}
	gid, e := strconv.Atoi(account.Gid)
	if e != nil || gid == 0 {
		return errors.New("invalid core group")
	}
	uid, e := strconv.Atoi(account.Uid)
	if e != nil || uid < 1 {
		return errors.New("invalid core user")
	}
	if e = prepareMihomo(profile, uid, gid); e != nil {
		return errors.New("cannot prepare authorized rule sets")
	}
	if _, e = syncDevices(ctx, policyMACs(i), n, gid); e != nil {
		return e
	}
	config, e := Compile(i, profile, cap, n, client.Secret)
	if e != nil {
		return e
	}
	if e = prepareGeo(ctx, config, profile); e != nil {
		return e
	}
	// Interface notices (address lifetimes, RA refreshes) usually change nothing; reloading
	// the core anyway would pause new connections and reset its DNS clients.
	digest, routing := sha256.Sum256(config), routingKey(i)
	if digest == last.config {
		return nil
	}
	if e = client.ReloadPayload(ctx, config); e != nil {
		return fmt.Errorf("core rejected the new configuration: %w", e)
	}
	if e = s.verifyChoices(ctx, config); e != nil {
		return e
	}
	// Mihomo keeps open connections on the route they started with. After a change of mode,
	// subscription or rules, close them all as Clash clients do, so browsers reconnect on the
	// new route: a page opened direct in smart mode would otherwise keep showing the local
	// address after switching to global.
	if routing != last.routing && client.CloseConnections(ctx) != nil {
		s.records.Log("core", "warn", "connections_not_reset")
	}
	s.records.CoreStarted(i.Source)
	s.restartMonitor(i, n, gid, client)
	s.mu.Lock()
	if s.applied != nil {
		s.applied.config = digest
		s.applied.routing = routing
	}
	s.mu.Unlock()
	return nil
}

// restartMonitor replaces the device watcher and connection recorder so they
// follow the reloaded policy.
func (s *System) restartMonitor(i Intent, n Network, gid int, client control.Client) {
	s.mu.Lock()
	if s.cancelMonitor != nil {
		s.cancelMonitor()
	}
	s.mu.Unlock()
	s.startMonitor(i, n, gid, client.Secret)
}
