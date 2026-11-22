package router

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"time"

	"github.com/openweir/openwrt/internal/netguard"
)

var errConflictInspection = errors.New("network resource conflict or incomplete inspection")

// resolveConflicts stops and disables the other proxy plugins holding the network, then reports
// what is left. A blocked result exits non-zero but still prints it.
var resolveConflicts = func(ctx context.Context) (netguard.Result, error) {
	cmd := exec.CommandContext(ctx, "/usr/sbin/openweir-net", "conflicts", "--resolve")
	cmd.WaitDelay = time.Second
	out, _ := cmd.Output()
	var r netguard.Result
	if json.Unmarshal(out, &r) != nil {
		return r, errConflictInspection
	}
	return r, nil
}

// clearConflicts runs on every start. Another proxy plugin is stopped and kept from starting at
// boot without asking; anything else that holds the network is named in the start error.
func (s *System) clearConflicts(ctx context.Context) error {
	r, err := resolveConflicts(ctx)
	if len(r.Stopped) > 0 {
		s.records.LogDetail("service", "warn", "conflict_services_stopped", strings.Join(r.Stopped, ", "))
	}
	if err != nil || !r.Blocked {
		return err
	}
	if len(r.Resources) == 0 {
		return errConflictInspection
	}
	held := make([]string, len(r.Resources))
	for i, v := range r.Resources {
		held[i] = v.Kind + " " + v.Name
	}
	return errors.New("network takeover blocked by: " + strings.Join(held, "; "))
}
