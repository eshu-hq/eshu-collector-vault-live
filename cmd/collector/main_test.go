// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	collector "github.com/eshu-hq/eshu-collector-vault-live"
	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

const (
	testToken       = "s.test-token"
	testRedactKey   = "cmd-test-redaction-key"
	testClusterID   = "vault-a"
	testNamespace   = "admin"
	testTokenEnvVar = "VAULT_TOKEN_TEST"
)

func testGetenv(key string) string {
	switch key {
	case testTokenEnvVar:
		return testToken
	case "ESHU_VAULT_LIVE_REDACTION_KEY":
		return testRedactKey
	}
	return ""
}

// stubVault serves the metadata endpoints the adapter reads for one
// kubernetes auth mount and one kv-v2 engine mount; every other path is a
// 404, which the adapter treats as absent. It asserts the read-only token and
// namespace arrive as headers, never as query params.
func stubVault(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Vault-Token"); got != testToken {
			t.Errorf("X-Vault-Token = %q, want the read-only token", got)
		}
		if got := r.Header.Get("X-Vault-Namespace"); got != testNamespace {
			t.Errorf("X-Vault-Namespace = %q, want %q", got, testNamespace)
		}
		if r.URL.Query().Get("token") != "" {
			t.Errorf("token arrived as a query param: %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/sys/auth":
			_, _ = io.WriteString(w, `{"data":{"kubernetes/":{"type":"kubernetes","accessor":"auth_k8s_a",`+
				`"local":false,"config":{},"options":{}}}}`)
		case "/v1/sys/mounts":
			_, _ = io.WriteString(w, `{"data":{"secret/":{"type":"kv","accessor":"kv_a",`+
				`"local":false,"config":{},"options":{"version":"2"}}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func claimScope(t *testing.T) string {
	t.Helper()
	scopeID, err := collector.VaultScopeID(testClusterID, testNamespace)
	if err != nil {
		t.Fatalf("VaultScopeID() error = %v", err)
	}
	return scopeID
}

func claimFor(baseURL string, t *testing.T) string {
	return claimForDeadline(baseURL, t, time.Now().UTC().Add(time.Hour))
}

func claimForDeadline(baseURL string, t *testing.T, deadline time.Time) string {
	now := deadline.UTC()
	raw, err := json.Marshal(map[string]any{
		"protocol_version": sdk.ProtocolVersionV1Alpha1,
		"claim": map[string]any{
			"component_id":   collector.ComponentID,
			"instance_id":    "vault-live-1",
			"collector_kind": collector.CollectorKind,
			"source_system":  collector.CollectorKind,
			"scope":          map[string]any{"id": claimScope(t), "kind": "vault_cluster"},
			"source_run_id":  "run-1",
			"generation_id":  "vault_live:generation-9",
			"work_item_id":   "work-1",
			"fencing_token":  "7",
			"attempt":        1,
			"deadline":       now.Add(time.Hour).Format(time.RFC3339Nano),
			"config_handle":  "component-config:vault-test",
		},
		"contract": collector.Contract(),
		"config": map[string]any{
			"collector_instance_id": "vault-live-1",
			"targets": []any{map[string]any{
				"vault_cluster_id": testClusterID,
				"namespace":        testNamespace,
				"address":          baseURL,
				"token_env":        testTokenEnvVar,
				"source_uri":       baseURL,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestRunClaimWritesOneValidResultToStdout(t *testing.T) {
	t.Parallel()

	server := stubVault(t)
	for _, args := range [][]string{nil, {"--sdk-stdio"}} {
		var stdout, stderr bytes.Buffer
		err := run(context.Background(), args, strings.NewReader(claimFor(server.URL, t)), &stdout, &stderr, testGetenv)
		if err != nil {
			t.Fatalf("run(%v) error = %v", args, err)
		}
		decoder := json.NewDecoder(&stdout)
		decoder.DisallowUnknownFields()
		var result sdk.Result
		if err := decoder.Decode(&result); err != nil {
			t.Fatalf("stdout is not one SDK result: %v", err)
		}
		if decoder.More() {
			t.Fatal("stdout carries more than one JSON value")
		}
		// One auth mount plus one secret engine mount; the KV walk finds no
		// metadata paths under the stub.
		if result.State != sdk.ResultComplete || len(result.Facts) != 2 {
			t.Fatalf("State=%q facts=%d, want complete with 2", result.State, len(result.Facts))
		}
		if result.Claim.FencingToken != "7" || result.Generation.ID != "vault_live:generation-9" {
			t.Fatalf("claim/generation not echoed: %+v %+v", result.Claim, result.Generation)
		}
		if result.Generation.FreshnessHint != "complete" {
			t.Fatalf("FreshnessHint=%q, want complete", result.Generation.FreshnessHint)
		}
		if _, err := sdk.NewValidator(collector.Contract()).ValidateResult(result); err != nil {
			t.Fatalf("ValidateResult() error = %v", err)
		}
	}
}

func TestRunClaimRejectsOversizeRequest(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer
	big := strings.NewReader(strings.Repeat("x", (1<<20)+1))
	if err := run(context.Background(), nil, big, &stdout, &stderr, testGetenv); err == nil {
		t.Fatal("run(oversize) = nil, want request limit rejection")
	}
	if stdout.Len() != 0 {
		t.Fatal("oversize request must not produce a result")
	}
}

func TestRunClaimRejectsExpiredDeadline(t *testing.T) {
	t.Parallel()

	server := stubVault(t)
	// The claim deadline is already past: the runner must refuse before any
	// Vault call.
	raw := claimForDeadline(server.URL, t, time.Now().UTC().Add(-time.Hour))
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), nil, strings.NewReader(raw), &stdout, &stderr, testGetenv); err == nil {
		t.Fatal("run(expired deadline) = nil, want deadline rejection")
	}
	if stdout.Len() != 0 {
		t.Fatal("expired claim must not produce a result")
	}
}

func TestRunClaimRejectsUnknownScope(t *testing.T) {
	t.Parallel()

	server := stubVault(t)
	raw := claimFor(server.URL, t)
	// Point the claim at a scope no target covers.
	raw = strings.Replace(raw, claimScope(t), "vault_live:missing-scope", 1)
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), nil, strings.NewReader(raw), &stdout, &stderr, testGetenv); err != nil {
		t.Fatalf("run() error = %v, want a retryable result, not a transport error", err)
	}
	var result sdk.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not one SDK result: %v", err)
	}
	if result.State != sdk.ResultRetryable {
		t.Fatalf("State=%q, want retryable", result.State)
	}
}
