// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

// mustScopeID returns the deterministic scope id for the test target.
func mustScopeID(t *testing.T, clusterID, namespace string) string {
	t.Helper()
	scopeID, err := VaultScopeID(clusterID, namespace)
	if err != nil {
		t.Fatalf("VaultScopeID(%q, %q) error = %v", clusterID, namespace, err)
	}
	return scopeID
}

func testClaim(t *testing.T) sdk.Claim {
	t.Helper()
	return sdk.Claim{
		ComponentID:   ComponentID,
		InstanceID:    "vault-live-1",
		CollectorKind: CollectorKind,
		SourceSystem:  CollectorKind,
		Scope:         sdk.Scope{ID: mustScopeID(t, "vault-a", "admin"), Kind: "vault_cluster"},
		SourceRunID:   "run-1",
		GenerationID:  "vault_live:generation-9",
		WorkItemID:    "work-1",
		FencingToken:  "7",
		Attempt:       1,
		Deadline:      time.Now().Add(time.Hour).UTC(),
		ConfigHandle:  "component-config:vault-test",
	}
}

func testHandlerSettings() map[string]any {
	return map[string]any{
		"collector_instance_id": "vault-live-1",
		"targets": []any{map[string]any{
			"vault_cluster_id": "vault-a",
			"namespace":        "admin",
			"address":          "https://a:8200",
			"token_env":        "VAULT_TOKEN_TEST",
			"source_uri":       "https://a:8200",
		}},
	}
}

// testHandlerEnv resolves the test token and redaction key from the fake
// environment.
func testHandlerEnv(t *testing.T, token string) func(string) string {
	t.Helper()
	return func(key string) string {
		switch key {
		case "VAULT_TOKEN_TEST":
			return token
		case envRedactionKey:
			return "handler-test-redaction-key"
		}
		return ""
	}
}

// fakeCollectClient returns a NewClient function serving canned metadata
// without HTTP.
func fakeCollectClient(client Client) func(SourceConfig) (*Collector, error) {
	return func(config SourceConfig) (*Collector, error) {
		return NewCollector(SourceConfig{
			CollectorInstanceID: config.CollectorInstanceID,
			Targets:             config.Targets,
			Key:                 config.Key,
			NewClient: func(TargetConfig) (Client, error) {
				return client, nil
			},
		})
	}
}

func mustHandle(t *testing.T, handler Handler, claim sdk.Claim, config map[string]any) sdk.Result {
	t.Helper()
	result, err := handler.Handle(context.Background(), sdk.Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config:          config,
	})
	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	return result
}

func mustValidate(t *testing.T, result sdk.Result) {
	t.Helper()
	if _, err := sdk.NewValidator(Contract()).ValidateResult(result); err != nil {
		t.Fatalf("ValidateResult() error = %v, want host acceptance", err)
	}
}

func TestHandleCompleteEchoesClaimAndValidates(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 16, 11, 0, 0, 0, time.UTC)
	handler := Handler{
		Getenv: testHandlerEnv(t, "s.test-token"),
		Now:    func() time.Time { return now },
		NewCollector: fakeCollectClient(&fakeVaultClient{
			authMounts: []AuthMount{{Path: "kubernetes/", Accessor: "acc", Method: "kubernetes"}},
		}),
	}
	claim := testClaim(t)
	result := mustHandle(t, handler, claim, testHandlerSettings())

	if result.State != sdk.ResultComplete {
		t.Fatalf("State = %q, want complete", result.State)
	}
	if result.Claim != claim {
		t.Fatalf("claim not echoed unchanged:\n got: %+v\nwant: %+v", result.Claim, claim)
	}
	if result.Generation.ID != claim.GenerationID {
		t.Fatalf("Generation.ID = %q, want %q", result.Generation.ID, claim.GenerationID)
	}
	if result.Generation.FreshnessHint != "complete" {
		t.Fatalf("FreshnessHint = %q, want complete for full coverage", result.Generation.FreshnessHint)
	}
	if len(result.Facts) != 1 {
		t.Fatalf("facts = %d, want 1", len(result.Facts))
	}
	for _, fact := range result.Facts {
		if fact.SourceRef.SourceSystem != claim.SourceSystem {
			t.Errorf("fact source system = %q, want claim %q", fact.SourceRef.SourceSystem, claim.SourceSystem)
		}
		if fact.SourceRef.ScopeID != claim.Scope.ID || fact.SourceRef.GenerationID != claim.GenerationID {
			t.Errorf("fact scope/generation binding lost: %+v", fact.SourceRef)
		}
	}
	mustValidate(t, result)
}

// TestHandleMarksPartialFreshnessOnCoverageWarning proves a generation with
// one failed family carries the partial freshness hint so status surfaces
// never read a partial snapshot as complete.
func TestHandleMarksPartialFreshnessOnCoverageWarning(t *testing.T) {
	t.Parallel()

	handler := Handler{
		Getenv: testHandlerEnv(t, "s.test-token"),
		NewCollector: fakeCollectClient(aclFailClient{&fakeVaultClient{
			authMounts: []AuthMount{{Path: "kubernetes/", Accessor: "acc", Method: "kubernetes"}},
		}}),
	}
	result := mustHandle(t, handler, testClaim(t), testHandlerSettings())

	if result.State != sdk.ResultComplete {
		t.Fatalf("State = %q, want complete (one family failure must not fail the generation)", result.State)
	}
	if result.Generation.FreshnessHint != "partial" {
		t.Fatalf("FreshnessHint = %q, want partial for partial coverage", result.Generation.FreshnessHint)
	}
	sawWarning := false
	for _, fact := range result.Facts {
		if fact.Kind == "secrets_iam_coverage_warning" {
			sawWarning = true
		}
	}
	if !sawWarning {
		t.Fatal("no coverage warning in the partial generation")
	}
	mustValidate(t, result)
}

func TestHandleUnknownScopeIsRetryable(t *testing.T) {
	t.Parallel()

	handler := Handler{Getenv: testHandlerEnv(t, "s.test-token")}
	claim := testClaim(t)
	claim.Scope.ID = "vault_live:missing-scope"
	result := mustHandle(t, handler, claim, testHandlerSettings())

	if result.State != sdk.ResultRetryable {
		t.Fatalf("State = %q, want retryable", result.State)
	}
	if result.Claim != claim {
		t.Fatalf("claim not echoed unchanged")
	}
	if len(result.Facts) != 0 {
		t.Fatalf("facts = %d, want none with a failure state", len(result.Facts))
	}
	mustValidate(t, result)
}

func TestHandleInvalidConfigIsTerminal(t *testing.T) {
	t.Parallel()

	handler := Handler{}
	result := mustHandle(t, handler, testClaim(t), map[string]any{})

	if result.State != sdk.ResultTerminal {
		t.Fatalf("State = %q, want terminal", result.State)
	}
	if len(result.Facts) != 0 {
		t.Fatalf("facts = %d, want none with a failure state", len(result.Facts))
	}
	mustValidate(t, result)
}

func TestHandleWrongCollectorKindErrors(t *testing.T) {
	t.Parallel()

	handler := Handler{}
	claim := testClaim(t)
	claim.CollectorKind = "jira"
	_, err := handler.Handle(context.Background(), sdk.Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config:          testHandlerSettings(),
	})
	if err == nil {
		t.Fatal("Handle(wrong kind) = nil, want host-bug error")
	}
}

func TestHandleWrongSourceSystemErrors(t *testing.T) {
	t.Parallel()

	handler := Handler{}
	claim := testClaim(t)
	claim.SourceSystem = "grafana"
	_, err := handler.Handle(context.Background(), sdk.Request{
		ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
		Claim:           claim,
		Contract:        Contract(),
		Config:          testHandlerSettings(),
	})
	if err == nil {
		t.Fatal("Handle(wrong source system) = nil, want foreign-claim rejection")
	}
}

// TestHandleRejectsBadFenceBeforeClientCall pins the in-tree admission: a
// missing or non-positive fencing token is rejected before the client factory
// runs.
func TestHandleRejectsBadFenceBeforeClientCall(t *testing.T) {
	t.Parallel()

	for _, fence := range []string{"", "  ", "0", "-3", "not-a-number"} {
		calls := 0
		handler := Handler{
			Getenv: testHandlerEnv(t, "s.test-token"),
			NewCollector: func(config SourceConfig) (*Collector, error) {
				calls++
				return NewCollector(config)
			},
		}
		claim := testClaim(t)
		claim.FencingToken = fence
		_, err := handler.Handle(context.Background(), sdk.Request{
			ProtocolVersion: sdk.ProtocolVersionV1Alpha1,
			Claim:           claim,
			Contract:        Contract(),
			Config:          testHandlerSettings(),
		})
		if err == nil {
			t.Fatalf("Handle(fence %q) = nil, want fence rejection", fence)
		}
		if calls != 0 {
			t.Fatalf("fence %q: collector built %d times, want 0 before fence validation", fence, calls)
		}
	}
}

func TestHandleNeverEmitsCredentials(t *testing.T) {
	t.Parallel()

	const secret = "VAULT-TOKEN-SECRET-8869"
	handler := Handler{
		Getenv: testHandlerEnv(t, secret),
		NewCollector: func(config SourceConfig) (*Collector, error) {
			if len(config.Targets) != 1 || config.Targets[0].Token != secret {
				t.Errorf("runtime target did not resolve the token from the environment")
			}
			return fakeCollectClient(&fakeVaultClient{
				authMounts: []AuthMount{{Path: "kubernetes/", Accessor: "acc", Method: "kubernetes"}},
			})(config)
		},
	}
	result := mustHandle(t, handler, testClaim(t), testHandlerSettings())

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Error("token reached the emitted result")
	}
	mustValidate(t, result)
}

// TestHandlerZeroValueReadsProcessEnv proves the documented zero value
// resolves token_env from the process environment instead of silently
// dropping it to blank.
func TestHandlerZeroValueReadsProcessEnv(t *testing.T) {
	const secret = "ZERO-VALUE-ENV-SECRET-8869"
	t.Setenv("VAULT_TOKEN_TEST", secret)
	t.Setenv(envRedactionKey, "zero-value-redaction-key")

	now := time.Date(2026, 5, 16, 11, 0, 0, 0, time.UTC)
	var gotToken string
	handler := Handler{
		Now: func() time.Time { return now },
		NewCollector: func(config SourceConfig) (*Collector, error) {
			if len(config.Targets) != 1 {
				t.Fatalf("targets = %d, want 1", len(config.Targets))
			}
			gotToken = config.Targets[0].Token
			return fakeCollectClient(&fakeVaultClient{
				authMounts: []AuthMount{{Path: "kubernetes/", Accessor: "acc", Method: "kubernetes"}},
			})(config)
		},
	}
	result := mustHandle(t, handler, testClaim(t), testHandlerSettings())

	if gotToken != secret {
		t.Fatalf("zero-value Handler resolved Token = %q, want process env %q", gotToken, secret)
	}
	if result.State != sdk.ResultComplete {
		t.Fatalf("State = %q, want complete", result.State)
	}
	mustValidate(t, result)
}
