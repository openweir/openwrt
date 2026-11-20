package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openweir/openwrt/internal/kernel"
)

func TestKernelJobRequiresConfirmedHealthOrVerifiedFallback(t *testing.T) {
	const next = "v1.19.34"
	const old = "v1.19.33"
	for _, tc := range []struct {
		name     string
		statuses []kernel.Status
		expect   string
	}{
		{"confirmed", []kernel.Status{{Selected: next, Active: old, Pending: true}, {Selected: next, Active: next}}, ""},
		{"restored", []kernel.Status{{Selected: next, Active: old}, {Selected: old, Active: old}}, "previous kernel v1.19.33 is running"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			i := 0
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			err := waitForKernel(ctx, next, old, func() (string, string, bool) { return "running", "", true }, func(context.Context) (kernel.Status, error) {
				if i >= len(tc.statuses) {
					t.Fatal("ignored final state")
				}
				s := tc.statuses[i]
				i++
				return s, nil
			})
			if i != len(tc.statuses) || (tc.expect == "" && err != nil) || (tc.expect != "" && (err == nil || !strings.Contains(err.Error(), tc.expect))) {
				t.Fatal("wrong task outcome", i, err)
			}
		})
	}
}
