package router

import (
	"context"
	"reflect"
	"testing"

	"github.com/openweir/openwrt/internal/netguard"
)

func TestStartClearsConflictingPlugins(t *testing.T) {
	saved := resolveConflicts
	t.Cleanup(func() { resolveConflicts = saved })
	for _, tc := range []struct {
		name   string
		result netguard.Result
		err    error
		want   string
		events []Event
	}{
		{name: "clear"},
		{
			name:   "stopped",
			result: netguard.Result{Stopped: []string{"openclash", "passwall"}},
			events: []Event{{Source: "service", Level: "warn", Message: "conflict_services_stopped", Detail: "openclash, passwall"}},
		},
		{
			name: "leftovers",
			result: netguard.Result{Blocked: true, Stopped: []string{"homeproxy"}, Resources: []netguard.Resource{
				{Kind: "nft", Name: "inet table passwall", Service: "passwall"},
				{Kind: "process", Name: "mihomo"},
				{Kind: "unverified", Name: "ubus"},
			}},
			want:   "network takeover blocked by: nft inet table passwall; process mihomo; unverified ubus",
			events: []Event{{Source: "service", Level: "warn", Message: "conflict_services_stopped", Detail: "homeproxy"}},
		},
		{name: "unnamed", result: netguard.Result{Blocked: true}, want: errConflictInspection.Error()},
		{name: "no report", err: errConflictInspection, want: errConflictInspection.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolveConflicts = func(context.Context) (netguard.Result, error) { return tc.result, tc.err }
			s := NewSystem()
			var got string
			if err := s.clearConflicts(context.Background()); err != nil {
				got = err.Error()
			}
			if got != tc.want {
				t.Fatalf("%q", got)
			}
			events := s.Records().Logs(0, 100, "", "", "")
			for i := range events {
				events[i].Time = 0
			}
			if len(events) != len(tc.events) || len(events) > 0 && !reflect.DeepEqual(events, tc.events) {
				t.Fatal(events)
			}
		})
	}
}
