// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"strings"
	"testing"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-collector-vault-live/document"
)

// Extraction parity (#8869): the contracts the extracted collector preserves
// — admission at schema 1.0.0, byte-identical stable ids and redaction
// markers, scope identity, generation binding, and credential redaction —
// proved against ported constructors, including hostile inputs.

// TestParityStableKeyGoldens pins three stable-id vectors computed from an
// independent oracle of the in-tree encoding ({"fact_type":...,
// "identity":...} with sorted keys and compact separators, SHA-256 hex), so
// the ported StableID is proved byte-identical to the core facts.StableID it
// replaces, not merely self-consistent.
func TestParityStableKeyGoldens(t *testing.T) {
	t.Parallel()

	if got, want := StableID("vault_auth_mount", map[string]any{
		"mount_join_key": "join-1", "vault_cluster_id": "vault-a",
	}), "f77d11727a9fe8fc36c1ee31571e74ca6ad5ab3b9b8b4a4b3e7dd299274f1ef6"; got != want {
		t.Errorf("mount stable key golden = %q, want %q", got, want)
	}
	if got, want := StableID("secrets_iam_coverage_warning", map[string]any{
		"generation": "g1", "resource_scope": "acl_policies", "source_state": "partial",
		"vault_cluster_id": "vault-a", "warning_kind": "partial_family",
	}), "26cfbacd333986d4185b3295cd1e5cd9b02c9b1269d76e98bb39dd8a98493cbd"; got != want {
		t.Errorf("warning stable key golden = %q, want %q", got, want)
	}
	if got, want := StableID("VaultLiveScope", map[string]any{
		"namespace": "admin", "vault_cluster_id": "vault-a",
	}), "de7d9d02c426ac00c84465828dc7cd1050bc6dc39bc5bcdddada8405fee3c754"; got != want {
		t.Errorf("scope stable key golden = %q, want %q", got, want)
	}
}

// TestParityFingerprintMarkerGolden pins the keyed-HMAC marker encoding
// against an independent oracle (HMAC-SHA256 over the length-prefixed
// redact.v1/reason/source/raw fields), so join keys computed here match the
// in-tree lane for the same key and inputs.
func TestParityFingerprintMarkerGolden(t *testing.T) {
	t.Parallel()

	key, err := newRedactionKey([]byte("vault-live-test-redaction-key"))
	if err != nil {
		t.Fatalf("newRedactionKey() error = %v", err)
	}
	ctx := EnvelopeContext{
		VaultClusterID: "vault-a", Namespace: "admin", ScopeID: "s", GenerationID: "g",
		CollectorInstanceID: "ci", FencingToken: 1, ObservedAt: time.Now().UTC(), Key: key,
	}
	got := ctx.fingerprintMountPath("kubernetes/")
	want := "redacted:hmac-sha256:7ab0eba7bea5743d1353b7ce52ed6b6bea47ceaf1608c1cf17e1e72c1d715ff0"
	if got != want {
		t.Errorf("fingerprint marker golden = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, redactionMarkerPrefix) {
		t.Errorf("marker %q lacks the keyed HMAC prefix", got)
	}
	// Determinism: the same input yields the same marker. The trailing-slash
	// spelling canonicalizes to the same marker as the bare path.
	if again := ctx.fingerprintMountPath("kubernetes"); again != got {
		t.Errorf("marker not deterministic across equivalent spellings: %q vs %q", got, again)
	}
	// Key separation: a different key yields a different marker.
	other, err := newRedactionKey([]byte("another-deployment-key"))
	if err != nil {
		t.Fatalf("newRedactionKey() error = %v", err)
	}
	otherCtx := ctx
	otherCtx.Key = other
	if same := otherCtx.fingerprintValue("mount_path", "kubernetes/"); same == got {
		t.Error("marker identical across keys; markers must be keyed")
	}
}

func parityContext(key redactionKey) EnvelopeContext {
	return EnvelopeContext{
		VaultClusterID:      "vault-a",
		Namespace:           "admin",
		ScopeID:             "vault_live:scope-1",
		GenerationID:        "vault_live:generation-9",
		CollectorInstanceID: "vault-live-1",
		FencingToken:        7,
		ObservedAt:          time.Date(2026, 5, 16, 11, 0, 0, 0, time.UTC),
		SourceURI:           "https://vault.example.com:8200",
		SourceSystem:        CollectorKind,
		Key:                 key,
	}
}

func TestParityAllKindsAdmitAtV1(t *testing.T) {
	t.Parallel()

	for _, kind := range document.FactKinds {
		version, ok := SchemaVersionFor(kind)
		if !ok || version != SchemaVersion {
			t.Errorf("SchemaVersionFor(%q) = %q, %v; want 1.0.0, true", kind, version, ok)
		}
		if err := ValidateSchemaVersion(kind, SchemaVersion); err != nil {
			t.Errorf("ValidateSchemaVersion(%q, 1.0.0) error = %v, want nil", kind, err)
		}
	}
	if err := ValidateSchemaVersion(document.KindAuthMount, "9.9.9"); err == nil {
		t.Error("ValidateSchemaVersion(mount, 9.9.9) = nil, want incompatible-schema rejection")
	}
	if err := ValidateSchemaVersion("vault.nope", "1.0.0"); err == nil {
		t.Error("ValidateSchemaVersion(unknown kind) = nil, want rejection")
	}
	if err := ValidateSchemaVersion("", "1.0.0"); err == nil {
		t.Error("ValidateSchemaVersion(blank kind) = nil, want rejection")
	}
}

// TestParityMountJoinKeysNormalizeEquivalentMountPaths pins the in-tree
// normalization: equivalent spellings share join keys and stable keys.
func TestParityMountJoinKeysNormalizeEquivalentMountPaths(t *testing.T) {
	t.Parallel()

	key := mustTestKey(t)
	first, err := NewAuthMountFact(parityContext(key), AuthMount{Path: "auth/kubernetes", Method: "kubernetes"}, "")
	if err != nil {
		t.Fatalf("NewAuthMountFact(first) error = %v", err)
	}
	next, err := NewAuthMountFact(parityContext(key), AuthMount{Path: "auth/kubernetes/", Method: "kubernetes"}, "")
	if err != nil {
		t.Fatalf("NewAuthMountFact(next) error = %v", err)
	}
	if first.StableKey != next.StableKey {
		t.Fatalf("StableKey changed for equivalent mount paths: %q vs %q", first.StableKey, next.StableKey)
	}
	if first.Payload["mount_join_key"] != next.Payload["mount_join_key"] {
		t.Fatalf("mount_join_key changed for equivalent mount paths: %q vs %q",
			first.Payload["mount_join_key"], next.Payload["mount_join_key"])
	}
}

// TestParityStableKeySurvivesGenerationRebind pins that stable keys are
// generation-independent while the source reference rebinds.
func TestParityStableKeySurvivesGenerationRebind(t *testing.T) {
	t.Parallel()

	key := mustTestKey(t)
	first, err := NewKVMetadataFact(parityContext(key), KVMetadata{
		MountPath: "secret/", Path: "payments/prod/api-key", CurrentVersion: 7,
	}, "")
	if err != nil {
		t.Fatalf("NewKVMetadataFact(first) error = %v", err)
	}
	rebound := parityContext(key)
	rebound.GenerationID = "vault_live:generation-10"
	rebound.FencingToken = 8
	second, err := NewKVMetadataFact(rebound, KVMetadata{
		MountPath: "secret/", Path: "payments/prod/api-key", CurrentVersion: 8,
	}, "")
	if err != nil {
		t.Fatalf("NewKVMetadataFact(second) error = %v", err)
	}
	if first.StableKey != second.StableKey {
		t.Errorf("StableKey changed across generations: %q vs %q", first.StableKey, second.StableKey)
	}
	if first.SourceRef.GenerationID == second.SourceRef.GenerationID {
		t.Error("SourceRef.GenerationID identical across generations; generation must rebind identity")
	}
	if second.SourceRef.GenerationID != rebound.GenerationID {
		t.Errorf("generation binding lost: %+v", second.SourceRef)
	}
	if second.SourceRef.FactKey != second.StableKey {
		t.Error("SourceRef.FactKey != StableKey")
	}
}

// TestParityGenerationBindingAndConfidence pins the host-facing contract for
// every builder: scope/generation binding, reported confidence, schema 1.0.0,
// and sanitized source refs.
func TestParityGenerationBindingAndConfidence(t *testing.T) {
	t.Parallel()

	key := mustTestKey(t)
	ctx := parityContext(key)
	cases := map[string]func() (sdk.Fact, error){
		"mount": func() (sdk.Fact, error) {
			return NewAuthMountFact(ctx, AuthMount{Path: "kubernetes/", Method: "kubernetes"}, "")
		},
		"role": func() (sdk.Fact, error) {
			return NewAuthRoleFact(ctx, AuthRole{MountPath: "kubernetes/", RoleName: "r", Method: "kubernetes"}, "")
		},
		"policy": func() (sdk.Fact, error) {
			return NewACLPolicyFact(ctx, ACLPolicy{PolicyName: "p"}, "")
		},
		"entity": func() (sdk.Fact, error) {
			return NewIdentityEntityFact(ctx, IdentityEntity{EntityID: "e"}, "")
		},
		"alias": func() (sdk.Fact, error) {
			return NewIdentityAliasFact(ctx, IdentityAlias{AliasID: "a", EntityID: "e", MountPath: "kubernetes/"}, "")
		},
		"kv": func() (sdk.Fact, error) {
			return NewKVMetadataFact(ctx, KVMetadata{MountPath: "secret/", Path: "p"}, "")
		},
		"engine": func() (sdk.Fact, error) {
			return NewSecretEngineMountFact(ctx, SecretEngineMount{MountPath: "secret/", MountType: "kv-v2"}, "")
		},
		"warning": func() (sdk.Fact, error) {
			return NewCoverageWarningFact(ctx, "kv_metadata", "")
		},
	}
	for name, build := range cases {
		fact, err := build()
		if err != nil {
			t.Fatalf("%s: error = %v", name, err)
		}
		if fact.SourceRef.ScopeID != ctx.ScopeID || fact.SourceRef.GenerationID != ctx.GenerationID {
			t.Errorf("%s: scope/generation binding lost: %+v", name, fact.SourceRef)
		}
		if fact.SourceRef.SourceSystem != CollectorKind {
			t.Errorf("%s: SourceRef.SourceSystem = %q, want %q", name, fact.SourceRef.SourceSystem, CollectorKind)
		}
		if fact.SourceConfidence != sdk.SourceConfidenceReported {
			t.Errorf("%s: SourceConfidence = %q, want reported", name, fact.SourceConfidence)
		}
		if fact.SchemaVersion != SchemaVersion {
			t.Errorf("%s: SchemaVersion = %q, want 1.0.0", name, fact.SchemaVersion)
		}
		if fact.StableKey == "" {
			t.Errorf("%s: StableKey is blank", name)
		}
		if fact.SourceRef.URI != ctx.SourceURI {
			t.Errorf("%s: SourceRef.URI = %q, want %q", name, fact.SourceRef.URI, ctx.SourceURI)
		}
		if fact.SourceRef.RecordID != fact.StableKey {
			t.Errorf("%s: SourceRef.RecordID != StableKey", name)
		}
	}
}

// TestParityCredentialedSourceURINeverPersists drives every builder with a
// credential-bearing Vault address and asserts the sentinel reaches no
// persisted field — the fact bytes the host commits.
func TestParityCredentialedSourceURINeverPersists(t *testing.T) {
	t.Parallel()

	const sentinel = "PARITY-SENTINEL-8869"
	key := mustTestKey(t)
	ctx := parityContext(key)
	ctx.SourceURI = "https://vaultuser:" + sentinel + "@vault.example.com:8200/v1/sys/auth?token=" + sentinel + "#frag"
	builders := map[string]func() (sdk.Fact, error){
		"mount": func() (sdk.Fact, error) {
			return NewAuthMountFact(ctx, AuthMount{Path: "kubernetes/", Method: "kubernetes"}, "")
		},
		"role": func() (sdk.Fact, error) {
			return NewAuthRoleFact(ctx, AuthRole{MountPath: "kubernetes/", RoleName: "r", Method: "kubernetes"}, "")
		},
		"policy": func() (sdk.Fact, error) {
			return NewACLPolicyFact(ctx, ACLPolicy{PolicyName: "p"}, "")
		},
		"entity": func() (sdk.Fact, error) {
			return NewIdentityEntityFact(ctx, IdentityEntity{EntityID: "e"}, "")
		},
		"alias": func() (sdk.Fact, error) {
			return NewIdentityAliasFact(ctx, IdentityAlias{AliasID: "a", EntityID: "e", MountPath: "kubernetes/"}, "")
		},
		"kv": func() (sdk.Fact, error) {
			return NewKVMetadataFact(ctx, KVMetadata{MountPath: "secret/", Path: "p"}, "")
		},
		"engine": func() (sdk.Fact, error) {
			return NewSecretEngineMountFact(ctx, SecretEngineMount{MountPath: "secret/", MountType: "kv-v2"}, "")
		},
		"warning": func() (sdk.Fact, error) {
			return NewCoverageWarningFact(ctx, "kv_metadata", "")
		},
	}
	for name, build := range builders {
		fact, err := build()
		if err != nil {
			t.Fatalf("%s: error = %v", name, err)
		}
		if strings.Contains(fact.SourceRef.URI, sentinel) {
			t.Errorf("%s: SourceRef.URI %q leaks credential material", name, fact.SourceRef.URI)
		}
		if fact.SourceRef.URI != "https://vault.example.com:8200/v1/sys/auth" {
			t.Errorf("%s: sanitized SourceURI = %q, want scheme://host/path", name, fact.SourceRef.URI)
		}
	}
}
