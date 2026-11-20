package main

import (
	"encoding/json"
	"testing"
)

func TestKernelRequestOwnsVerification(t *testing.T) {
	for _, key := range []string{"sha256", "cache", "capabilities", "manifest", "stage_only"} {
		args := map[string]json.RawMessage{"tag": json.RawMessage(`"v1.19.34"`), key: json.RawMessage(`"custom"`)}
		if _, err := checkKernelArgs("install-json", args); err == nil {
			t.Errorf("LuCI accepted caller-defined %s", key)
		}
	}
	args := map[string]json.RawMessage{"tag": json.RawMessage(`"v1.19.34"`), "mirror": json.RawMessage(`"https://example.com"`)}
	if _, err := checkKernelArgs("install-json", args); err != nil {
		t.Fatal(err)
	}
	if _, err := checkKernelArgs("rollback", args); err == nil {
		t.Fatal("rollback accepted an installation source")
	}
}

func TestKernelErrorDoesNotExposeSource(t *testing.T) {
	for input, want := range map[string]string{
		"release file size or SHA-256 mismatch\n":                                "release checksum mismatch",
		"cannot verify original release via GitHub: https://example.com/private": "upstream release checksum unavailable",
		"open /tmp/private-credential: permission denied":                        "kernel operation failed",
	} {
		if got := publicKernelError(input).Error(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}
