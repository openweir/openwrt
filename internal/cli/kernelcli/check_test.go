package kernelcli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckErrorsIdentifyNodeAndFieldWithoutCoreOutput(t *testing.T) {
	const node = "node:000000000000000000000000000000ab"
	path := filepath.Join(t.TempDir(), "candidate.yaml")
	if err := os.WriteFile(path, []byte("proxies:\n  - {name: first, type: ss}\n  - {name: "+node+", type: snell, psk: private-secret}"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ diagnostic, object, contains string }{
		{"proxy 1: invalid psk private-secret", node, "snell configuration"},
		{"proxy group[3]: private-secret", "proxy group[3]", "rejected"},
		{"rules[2]: private-secret", "rules[2]", "rejected"},
		{"failed: password=private-secret", "configuration", "rejected"},
	} {
		r := rejection(path, tt.diagnostic)
		if r.Object != tt.object || !strings.Contains(r.Reason, tt.contains) || strings.Contains(r.Error(), "private") {
			t.Errorf("unexpected diagnostic: %+v", r)
		}
	}
}

func TestLaunchIssueKeepsOnlyKnownFailureClasses(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{context.DeadlineExceeded, "kernel_validation_timeout"},
		{&os.PathError{Op: "open", Path: "secret/config.json", Err: os.ErrPermission}, "kernel_permission_denied"},
		{errors.New("insufficient storage for the config snapshot and reserve"), "kernel_storage_reserve"},
		{errors.New("sensitive embedded reason"), "kernel_preparation_failed"},
	} {
		if got := launchIssue(tc.err); got.Reason != tc.reason || got.Object != "" {
			t.Fatal(got)
		}
	}
}
