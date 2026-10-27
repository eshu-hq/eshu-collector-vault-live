// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package runtime

import (
	"testing"
)

func mustTestKey(t *testing.T) Key {
	t.Helper()
	key, err := NewKey([]byte("test-deployment-redaction-key"))
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return key
}

// TestConfigValidatedFailClosed proves the construction contract rejects
// incomplete or ambiguous configs instead of defaulting them: blank instance
// identity, no targets, a zero redaction key, a blank cluster id, and a
// duplicate target scope all fail.
func TestConfigValidatedFailClosed(t *testing.T) {
	t.Parallel()

	valid := Config{
		CollectorInstanceID: "vault-live-qa-1",
		RedactionKey:        mustTestKey(t),
		Targets: []ClusterTarget{
			{VaultClusterID: "cluster-a", Namespace: "ns-1"},
		},
	}

	cases := map[string]func(*Config){
		"blank instance id": func(c *Config) { c.CollectorInstanceID = "  " },
		"no targets":        func(c *Config) { c.Targets = nil },
		"zero redaction key": func(c *Config) {
			c.RedactionKey = Key{}
		},
		"blank cluster id": func(c *Config) { c.Targets[0].VaultClusterID = "" },
		"duplicate scope": func(c *Config) {
			c.Targets = append(c.Targets, ClusterTarget{VaultClusterID: "cluster-a", Namespace: "ns-1"})
		},
	}
	for name, mutate := range cases {
		cfg := valid
		cfg.Targets = append([]ClusterTarget(nil), valid.Targets...)
		mutate(&cfg)
		if _, err := cfg.validated(); err == nil {
			t.Errorf("validated() accepted %s", name)
		}
	}

	if _, err := valid.validated(); err != nil {
		t.Errorf("validated() rejected a complete config: %v", err)
	}
}

// TestNewKeyRejectsBlankMaterial proves the redaction-key handle cannot be
// built from empty material: unkeyed markers would be guessable.
func TestNewKeyRejectsBlankMaterial(t *testing.T) {
	t.Parallel()

	for _, material := range [][]byte{nil, {}, []byte("   ")} {
		if _, err := NewKey(material); err == nil {
			t.Errorf("NewKey accepted blank material %q", material)
		}
	}
}
