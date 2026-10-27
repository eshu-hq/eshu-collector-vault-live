// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"strings"
	"testing"
)

func envFromMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func vaultTestConfig(tokenEnv string) map[string]any {
	return map[string]any{
		"collector_instance_id": "vault-live-1",
		"targets": []any{map[string]any{
			"vault_cluster_id": "vault-a",
			"namespace":        "admin",
			"address":          "https://a:8200",
			"token_env":        tokenEnv,
			"source_uri":       "https://a:8200",
		}},
	}
}

func TestParseSettingsResolvesTokenFromEnv(t *testing.T) {
	t.Parallel()

	getenv := envFromMap(map[string]string{
		"VAULT_TOKEN_A": "s.readonly-token",
		envRedactionKey: "vault-redaction-key",
	})
	settings, err := ParseSettings(vaultTestConfig("VAULT_TOKEN_A"), getenv)
	if err != nil {
		t.Fatalf("ParseSettings() error = %v", err)
	}
	if len(settings.Source.Targets) != 1 || settings.Source.Targets[0].VaultClusterID != "vault-a" {
		t.Fatalf("targets = %+v", settings.Source.Targets)
	}
	if settings.Key.isZero() {
		t.Fatalf("redaction key is zero, want resolved key from %s", envRedactionKey)
	}
	target := settings.Source.Targets[0]
	if target.Token != "s.readonly-token" || target.Address != "https://a:8200" || target.Namespace != "admin" {
		t.Fatalf("target = %+v", target)
	}
	if target.ScopeID == "" {
		t.Fatal("target scope id was not derived")
	}
	wantScope, err := VaultScopeID("vault-a", "admin")
	if err != nil {
		t.Fatalf("VaultScopeID() error = %v", err)
	}
	if target.ScopeID != wantScope {
		t.Fatalf("target scope = %q, want deterministic %q", target.ScopeID, wantScope)
	}
}

func TestParseSettingsAllowsMultipleNamespacesPerCluster(t *testing.T) {
	t.Parallel()

	getenv := envFromMap(map[string]string{
		envRedactionKey: "vault-redaction-key",
		"T_ADMIN":       "tok-admin",
		"T_TEAM":        "tok-team",
	})
	config := map[string]any{
		"collector_instance_id": "ci",
		"targets": []any{
			map[string]any{"vault_cluster_id": "vault-a", "namespace": "admin", "address": "https://a", "token_env": "T_ADMIN"},
			map[string]any{"vault_cluster_id": "vault-a", "namespace": "team", "address": "https://a", "token_env": "T_TEAM"},
		},
	}
	settings, err := ParseSettings(config, getenv)
	if err != nil {
		t.Fatalf("ParseSettings() error = %v (multi-namespace per cluster must be allowed)", err)
	}
	if len(settings.Source.Targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(settings.Source.Targets))
	}
	if settings.Source.Targets[0].Token != "tok-admin" || settings.Source.Targets[1].Token != "tok-team" {
		t.Fatalf("per-namespace tokens not keyed distinctly: %+v", settings.Source.Targets)
	}
	if settings.Source.Targets[0].ScopeID == settings.Source.Targets[1].ScopeID {
		t.Fatal("namespace targets share a scope id; the namespace dimension must be honored")
	}
}

func TestParseSettingsDuplicateTargetErrorHidesRawNamespace(t *testing.T) {
	t.Parallel()

	getenv := envFromMap(map[string]string{
		envRedactionKey: "vault-redaction-key",
		"T_ADMIN":       "tok-admin",
		"T_ADMIN_2":     "tok-admin-2",
	})
	config := map[string]any{
		"collector_instance_id": "ci",
		"targets": []any{
			map[string]any{"vault_cluster_id": "vault-a", "namespace": "admin", "address": "https://a", "token_env": "T_ADMIN"},
			map[string]any{"vault_cluster_id": "vault-a", "namespace": "admin", "address": "https://a", "token_env": "T_ADMIN_2"},
		},
	}
	_, err := ParseSettings(config, getenv)
	if err == nil {
		t.Fatal("ParseSettings() error = nil, want duplicate-target error")
	}
	if strings.Contains(err.Error(), "vault-a") || strings.Contains(err.Error(), "admin") {
		t.Fatalf("duplicate-target error exposed raw target identity: %v", err)
	}
}

// TestParseSettingsRejectsInlineToken is the RED half of the no-token-in-config
// boundary: a target that names the token inline fails closed, and the error
// never echoes the value.
func TestParseSettingsRejectsInlineToken(t *testing.T) {
	t.Parallel()

	const secret = "INLINE-TOKEN-SENTINEL-8869"
	for _, key := range []string{"token", "vault_token", "auth_token", "secret", "password", "credential", "api_key"} {
		config := vaultTestConfig("VAULT_TOKEN_A")
		config["targets"].([]any)[0].(map[string]any)[key] = secret
		getenv := envFromMap(map[string]string{
			"VAULT_TOKEN_A": "s.readonly-token",
			envRedactionKey: "vault-redaction-key",
		})
		_, err := ParseSettings(config, getenv)
		if err == nil {
			t.Fatalf("ParseSettings(%q inline) = nil, want no-token-in-config rejection", key)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("rejection for %q echoes the secret value: %v", key, err)
		}
	}
}

// TestParseSettingsAcceptsTokenEnvPointer is the GREEN half of the
// no-token-in-config boundary: the sanctioned token_env pointer resolves and
// the error-free config carries the token only in the runtime-only field.
func TestParseSettingsAcceptsTokenEnvPointer(t *testing.T) {
	t.Parallel()

	const secret = "GREEN-POINTER-SECRET-8869"
	getenv := envFromMap(map[string]string{
		"VAULT_TOKEN_A": secret,
		envRedactionKey: "vault-redaction-key",
	})
	settings, err := ParseSettings(vaultTestConfig("VAULT_TOKEN_A"), getenv)
	if err != nil {
		t.Fatalf("ParseSettings(token_env) error = %v, want the sanctioned pointer accepted", err)
	}
	if settings.Source.Targets[0].Token != secret {
		t.Fatal("token_env pointer did not resolve into the runtime-only field")
	}
}

func TestParseSettingsErrors(t *testing.T) {
	t.Parallel()

	withEnv := func(env map[string]string) map[string]string {
		env[envRedactionKey] = "vault-redaction-key"
		return env
	}
	cases := map[string]struct {
		config map[string]any
		env    map[string]string
	}{
		"missing instance id": {vaultTestConfig("T"), withEnv(map[string]string{"T": "tok"})},
		"missing targets": {
			map[string]any{"collector_instance_id": "ci"},
			withEnv(map[string]string{}),
		},
		"empty targets": {
			map[string]any{"collector_instance_id": "ci", "targets": []any{}},
			withEnv(map[string]string{}),
		},
		"blank cluster id": {
			map[string]any{"collector_instance_id": "ci", "targets": []any{map[string]any{
				"address": "https://v", "token_env": "T",
			}}},
			withEnv(map[string]string{"T": "tok"}),
		},
		"missing address": {
			map[string]any{"collector_instance_id": "ci", "targets": []any{map[string]any{
				"vault_cluster_id": "v", "token_env": "T",
			}}},
			withEnv(map[string]string{"T": "tok"}),
		},
		"missing token env": {
			map[string]any{"collector_instance_id": "ci", "targets": []any{map[string]any{
				"vault_cluster_id": "v", "address": "https://v",
			}}},
			withEnv(map[string]string{}),
		},
		"empty token": {
			map[string]any{"collector_instance_id": "ci", "targets": []any{map[string]any{
				"vault_cluster_id": "v", "address": "https://v", "token_env": "T",
			}}},
			withEnv(map[string]string{}),
		},
		"missing redaction key": {
			vaultTestConfig("T"),
			map[string]string{"T": "tok"},
		},
	}
	// The missing-instance-id case needs its instance id blanked.
	cases["missing instance id"].config["collector_instance_id"] = "  "
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseSettings(tc.config, envFromMap(tc.env)); err == nil {
				t.Fatalf("%s: ParseSettings err = nil, want error", name)
			}
		})
	}
}

// TestParseSettingsNilGetenvReadsProcessEnv proves a nil getenv falls back to
// the process environment instead of silently resolving every token to blank.
func TestParseSettingsNilGetenvReadsProcessEnv(t *testing.T) {
	const secret = "PARSE-SETTINGS-ENV-SECRET-8869"
	t.Setenv("VAULT_TOKEN_PROC", secret)
	t.Setenv(envRedactionKey, "proc-redaction-key")

	settings, err := ParseSettings(vaultTestConfig("VAULT_TOKEN_PROC"), nil)
	if err != nil {
		t.Fatalf("ParseSettings() error = %v, want nil", err)
	}
	if settings.Source.Targets[0].Token != secret {
		t.Fatalf("Token = %q, want process env %q", settings.Source.Targets[0].Token, secret)
	}
}
