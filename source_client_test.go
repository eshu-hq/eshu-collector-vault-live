// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"net/http/httptest"
	"testing"
)

// TestDefaultVaultClientSelectsAdapter proves the nil-factory path builds a
// live adapter (and rejects a bad target) without touching the network.
func TestDefaultVaultClientSelectsAdapter(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(nil)
	defer srv.Close()
	c, err := defaultVaultClient(TargetConfig{Address: srv.URL, Token: "tok"})
	if err != nil || c == nil {
		t.Fatalf("client = %v err = %v", c, err)
	}
	if _, err := defaultVaultClient(TargetConfig{Address: "://bad", Token: "tok"}); err == nil {
		t.Fatal("bad address should fail")
	}
}
