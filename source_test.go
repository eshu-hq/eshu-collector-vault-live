// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eshu-hq/eshu-collector-vault-live/document"
)

// fakeVaultClient is a metadata-only test double returning canned metadata
// for each Vault fact family.
type fakeVaultClient struct {
	authMounts   []AuthMount
	authRoles    []AuthRole
	aclPolicies  []ACLPolicy
	entities     []IdentityEntity
	aliases      []IdentityAlias
	kvMetadata   []KVMetadata
	engineMounts []SecretEngineMount
}

func (c *fakeVaultClient) ListAuthMounts(context.Context) ([]AuthMount, error) {
	return append([]AuthMount(nil), c.authMounts...), nil
}

func (c *fakeVaultClient) ListAuthRoles(context.Context) ([]AuthRole, error) {
	return append([]AuthRole(nil), c.authRoles...), nil
}

func (c *fakeVaultClient) ListACLPolicies(context.Context) ([]ACLPolicy, error) {
	return append([]ACLPolicy(nil), c.aclPolicies...), nil
}

func (c *fakeVaultClient) ListIdentityEntities(context.Context) ([]IdentityEntity, error) {
	return append([]IdentityEntity(nil), c.entities...), nil
}

func (c *fakeVaultClient) ListIdentityAliases(context.Context) ([]IdentityAlias, error) {
	return append([]IdentityAlias(nil), c.aliases...), nil
}

func (c *fakeVaultClient) ListKVMetadata(context.Context) ([]KVMetadata, error) {
	return append([]KVMetadata(nil), c.kvMetadata...), nil
}

func (c *fakeVaultClient) ListSecretEngineMounts(context.Context) ([]SecretEngineMount, error) {
	return append([]SecretEngineMount(nil), c.engineMounts...), nil
}

func testTarget() TargetConfig {
	return TargetConfig{
		VaultClusterID: "vault-prod",
		Namespace:      "admin",
		ScopeID:        "vault_live:test-scope",
		Address:        "https://vault.example.com:8200",
		Token:          "test-token",
		SourceURI:      "https://vault.example.com:8200/v1/sys/auth",
	}
}

func testBoundary() Boundary {
	return Boundary{
		ScopeID:             "vault_live:test-scope",
		GenerationID:        "vault_live:generation-1",
		CollectorInstanceID: "vault-live-1",
		FencingToken:        7,
		ObservedAt:          time.Unix(1700000000, 0).UTC(),
		SourceSystem:        CollectorKind,
	}
}

func testCollector(t *testing.T, client Client) *Collector {
	t.Helper()
	collector, err := NewCollector(SourceConfig{
		CollectorInstanceID: "vault-live-1",
		Targets:             []TargetConfig{testTarget()},
		Key:                 mustTestKey(t),
		NewClient: func(TargetConfig) (Client, error) {
			return client, nil
		},
	})
	if err != nil {
		t.Fatalf("NewCollector() error = %v", err)
	}
	return collector
}

// TestCollectEmitsAllSevenFactFamilies proves Collector.Collect maps every
// Vault metadata fact family through the redacted SDK envelope builders.
func TestCollectEmitsAllSevenFactFamilies(t *testing.T) {
	t.Parallel()

	client := &fakeVaultClient{
		authMounts: []AuthMount{{Path: "kubernetes/", Accessor: "auth_k8s_a", Method: "kubernetes"}},
		authRoles: []AuthRole{{
			MountPath: "kubernetes/", RoleName: "payments-api", Method: "kubernetes",
			KubernetesClusterID:           "cluster-prod",
			BoundServiceAccountNames:      []string{"payments"},
			BoundServiceAccountNamespaces: []string{"prod"},
			TokenPolicyNames:              []string{"payments-read"},
		}},
		aclPolicies: []ACLPolicy{{
			PolicyName: "payments-read", PolicyHash: "sha256:pol",
			Rules: []ACLRule{{Path: "secret/metadata/payments", Capabilities: []string{"read", "list"}}},
		}},
		entities:     []IdentityEntity{{EntityID: "ent-1", EntityName: "payments", AliasCount: 1}},
		aliases:      []IdentityAlias{{AliasID: "alias-1", EntityID: "ent-1", MountPath: "kubernetes/", MountAccessor: "auth_k8s_a", AliasName: "payments"}},
		kvMetadata:   []KVMetadata{{MountPath: "secret/", Path: "payments/db", CurrentVersion: 3, MaxVersions: 10, CustomMetadataKeys: []string{"owner"}}},
		engineMounts: []SecretEngineMount{{MountPath: "secret/", MountAccessor: "kv_a", MountType: "kv-v2", KVVersion: "2"}},
	}

	facts, observedAt, err := testCollector(t, client).Collect(context.Background(), testTarget(), testBoundary())
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil", err)
	}
	if observedAt.IsZero() {
		t.Fatal("Collect() returned zero observedAt")
	}
	got := map[string]int{}
	for _, fact := range facts {
		got[fact.Kind]++
		if fact.SourceRef.ScopeID != testBoundary().ScopeID || fact.SourceRef.GenerationID != testBoundary().GenerationID {
			t.Fatalf("fact scope/generation binding lost: %+v", fact.SourceRef)
		}
	}
	for _, kind := range []string{
		document.KindAuthMount,
		document.KindAuthRole,
		document.KindACLPolicy,
		document.KindIdentityEntity,
		document.KindIdentityAlias,
		document.KindKVMetadata,
		document.KindSecretEngineMount,
	} {
		if got[kind] != 1 {
			t.Fatalf("fact kind %q emitted %d times, want 1 (got: %v)", kind, got[kind], got)
		}
	}
}

// TestCollectNeverEmitsRawSecretMaterial proves the redaction boundary end to
// end: no raw Vault value reaches any emitted payload.
func TestCollectNeverEmitsRawSecretMaterial(t *testing.T) {
	t.Parallel()

	sentinels := []string{
		"RAWNAMESPACE-team", "RAWMOUNT-kubernetes/", "RAWROLE-payments",
		"RAWNS-prod", "RAWPOLICY-read", "RAWACLPATH-secret/metadata/payments",
		"RAWENTID-1", "RAWKVMOUNT-secret/", "RAWKVPATH-payments/db", "RAWCMK-owner",
	}
	client := &fakeVaultClient{
		authMounts: []AuthMount{{Path: "RAWMOUNT-kubernetes/", Accessor: "acc", Method: "kubernetes"}},
		authRoles: []AuthRole{{
			MountPath: "RAWMOUNT-kubernetes/", RoleName: "RAWROLE-payments", Method: "kubernetes",
			KubernetesClusterID:           "cluster-prod",
			BoundServiceAccountNames:      []string{"payments"},
			BoundServiceAccountNamespaces: []string{"RAWNS-prod"},
			TokenPolicyNames:              []string{"RAWPOLICY-read"},
		}},
		aclPolicies: []ACLPolicy{{
			PolicyName: "p", PolicyHash: "sha256:abc",
			Rules: []ACLRule{{Path: "RAWACLPATH-secret/metadata/payments", Capabilities: []string{"read"}}},
		}},
		entities:     []IdentityEntity{{EntityID: "RAWENTID-1", EntityName: "e"}},
		kvMetadata:   []KVMetadata{{MountPath: "RAWKVMOUNT-secret/", Path: "RAWKVPATH-payments/db", CustomMetadataKeys: []string{"RAWCMK-owner"}}},
		engineMounts: []SecretEngineMount{{MountPath: "secret/", MountAccessor: "kv_a", MountType: "kv-v2", KVVersion: "2"}},
	}
	target := testTarget()
	target.Namespace = "RAWNAMESPACE-team"

	facts, _, err := testCollector(t, client).Collect(context.Background(), target, testBoundary())
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil", err)
	}
	if len(facts) == 0 {
		t.Fatal("Collect() emitted no facts; cannot assert redaction")
	}
	for _, fact := range facts {
		for key, val := range fact.Payload {
			for _, sentinel := range sentinels {
				if envelopePayloadContains(val, sentinel) {
					t.Fatalf("fact %q payload[%q] leaks raw Vault material %q", fact.Kind, key, sentinel)
				}
			}
		}
	}
}

// TestCollectSanitizesCredentialBearingSourceURI proves a Vault endpoint URL
// carrying basic-auth userinfo or a token query parameter is stripped to
// scheme://host/path before it can reach a fact's SourceRef.
func TestCollectSanitizesCredentialBearingSourceURI(t *testing.T) {
	t.Parallel()

	target := testTarget()
	target.SourceURI = "https://vaultuser:s3cr3t-token@vault.example.com:8200/v1/sys/auth?token=abcd1234#frag"
	client := &fakeVaultClient{authMounts: []AuthMount{{Path: "kubernetes/", Accessor: "acc", Method: "kubernetes"}}}

	facts, _, err := testCollector(t, client).Collect(context.Background(), target, testBoundary())
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil", err)
	}
	if len(facts) == 0 {
		t.Fatal("Collect() emitted no facts")
	}
	for _, leak := range []string{"s3cr3t-token", "vaultuser", "token=abcd1234", "abcd1234"} {
		for _, fact := range facts {
			if strings.Contains(fact.SourceRef.URI, leak) {
				t.Fatalf("SourceRef.URI %q leaks credential material %q", fact.SourceRef.URI, leak)
			}
		}
	}
	if got, want := facts[0].SourceRef.URI, "https://vault.example.com:8200/v1/sys/auth"; got != want {
		t.Fatalf("sanitized SourceURI = %q, want %q", got, want)
	}
}

// TestClientSurfaceIsMetadataOnly proves, structurally, that the Vault Client
// seam exposes no operation that reads a secret value. This guards the
// metadata-only contract against future methods that would read KV /data,
// tokens, or secret ids.
func TestClientSurfaceIsMetadataOnly(t *testing.T) {
	t.Parallel()

	forbidden := []string{"getsecret", "readsecret", "readdata", "kvdata", "secretid", "token", "unwrap"}
	clientType := reflect.TypeOf((*Client)(nil)).Elem()
	for i := 0; i < clientType.NumMethod(); i++ {
		name := strings.ToLower(clientType.Method(i).Name)
		for _, bad := range forbidden {
			if strings.Contains(name, bad) {
				t.Fatalf("Client exposes value-reading method %q (contains %q); the lane must stay metadata-only", clientType.Method(i).Name, bad)
			}
		}
	}
}

// aclFailClient errors only on ListACLPolicies to exercise per-family resilience.
type aclFailClient struct{ *fakeVaultClient }

func (c aclFailClient) ListACLPolicies(context.Context) ([]ACLPolicy, error) {
	return nil, errors.New("permission denied reading /sys/policies/acl at https://vault.example.com")
}

func TestCollectIsResilientToOneFamilyFailure(t *testing.T) {
	t.Parallel()

	base := &fakeVaultClient{authMounts: []AuthMount{{Path: "kubernetes/", Accessor: "acc", Method: "kubernetes"}}}
	facts, _, err := testCollector(t, aclFailClient{base}).Collect(context.Background(), testTarget(), testBoundary())
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil (one family failure must not fail the generation)", err)
	}

	var sawAuthMount, sawWarning bool
	for _, fact := range facts {
		switch fact.Kind {
		case document.KindAuthMount:
			sawAuthMount = true
		case document.KindCoverageWarning:
			sawWarning = true
			if got := fact.Payload["resource_scope"]; got != vaultFamilyACLPolicies {
				t.Fatalf("coverage warning resource_scope = %q, want %q", got, vaultFamilyACLPolicies)
			}
			if got := fact.Payload["source_state"]; got != "partial" {
				t.Fatalf("coverage warning source_state = %q, want partial", got)
			}
		}
		// The raw Vault error (path + address) must never reach the fact.
		for key, val := range fact.Payload {
			if s, ok := val.(string); ok && (strings.Contains(s, "/sys/policies/acl") || strings.Contains(s, "vault.example.com")) {
				t.Fatalf("payload[%q] = %q leaks the raw Vault error", key, s)
			}
		}
		if got, want := fact.SourceRef.URI, testTarget().SourceURI; got != want {
			t.Fatalf("SourceRef.URI = %q, want the sanitized target endpoint %q", got, want)
		}
	}
	if !sawAuthMount {
		t.Fatal("other families were not collected after the ACL family failed")
	}
	if !sawWarning {
		t.Fatalf("no %s emitted for the failed family", document.KindCoverageWarning)
	}
	if hasCoverageWarning(facts) != sawWarning {
		t.Fatal("hasCoverageWarning disagrees with the emitted facts")
	}
}

// cancelClient fails only on ListAuthMounts with the context error.
type cancelClient struct{ *fakeVaultClient }

func (c cancelClient) ListAuthMounts(ctx context.Context) ([]AuthMount, error) {
	return nil, ctx.Err()
}

func TestCollectContextCancellationIsFatal(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := testCollector(t, cancelClient{&fakeVaultClient{}}).Collect(ctx, testTarget(), testBoundary())
	if err == nil {
		t.Fatal("Collect() error = nil, want fatal on context cancellation")
	}
}

// TestCollectFallsBackToAddressForSourceURI proves the target address backs
// the fact SourceRef URI when no explicit source_uri is configured, so the
// host-required URI is never blank.
func TestCollectFallsBackToAddressForSourceURI(t *testing.T) {
	t.Parallel()

	target := testTarget()
	target.SourceURI = ""
	client := &fakeVaultClient{authMounts: []AuthMount{{Path: "kubernetes/", Accessor: "acc", Method: "kubernetes"}}}

	facts, _, err := testCollector(t, client).Collect(context.Background(), target, testBoundary())
	if err != nil {
		t.Fatalf("Collect() error = %v, want nil", err)
	}
	if len(facts) == 0 {
		t.Fatal("Collect() emitted no facts")
	}
	for _, fact := range facts {
		if got, want := fact.SourceRef.URI, "https://vault.example.com:8200"; got != want {
			t.Fatalf("SourceRef.URI = %q, want sanitized target address %q", got, want)
		}
	}
}

// TestSanitizeVaultSourceURI pins the provenance sanitizer: userinfo, query,
// and fragment are stripped; unparseable values are dropped, never leaked.
func TestSanitizeVaultSourceURI(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"https://vault.example.com:8200/v1/sys/auth":    "https://vault.example.com:8200/v1/sys/auth",
		"https://u:p@vault.example.com/v1?token=x#frag": "https://vault.example.com/v1",
		"":                     "",
		"  ":                   "",
		"not a url at all :::": "",
		"/relative/path":       "",
	}
	for input, want := range cases {
		if got := sanitizeVaultSourceURI(input); got != want {
			t.Errorf("sanitizeVaultSourceURI(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestCollectorValidatesConfig pins fail-closed construction: blank instance
// identity, a zero redaction key, no targets, a blank cluster id, and a
// duplicate scope id are all rejected.
func TestCollectorValidatesConfig(t *testing.T) {
	t.Parallel()

	valid := SourceConfig{
		CollectorInstanceID: "vault-live-1",
		Targets:             []TargetConfig{{VaultClusterID: "a", ScopeID: "s"}},
		Key:                 mustTestKey(t),
	}
	cases := map[string]func(*SourceConfig){
		"blank instance id": func(c *SourceConfig) { c.CollectorInstanceID = "  " },
		"zero redaction key": func(c *SourceConfig) {
			c.Key = redactionKey{}
		},
		"no targets":       func(c *SourceConfig) { c.Targets = nil },
		"blank cluster id": func(c *SourceConfig) { c.Targets[0].VaultClusterID = "" },
		"blank scope id":   func(c *SourceConfig) { c.Targets[0].ScopeID = "" },
		"duplicate scope": func(c *SourceConfig) {
			c.Targets = append(c.Targets, TargetConfig{VaultClusterID: "b", ScopeID: "s"})
		},
	}
	for name, mutate := range cases {
		cfg := valid
		cfg.Targets = append([]TargetConfig(nil), valid.Targets...)
		mutate(&cfg)
		if _, err := NewCollector(cfg); err == nil {
			t.Errorf("NewCollector() accepted %s", name)
		}
	}
	if _, err := NewCollector(valid); err != nil {
		t.Errorf("NewCollector() rejected a complete config: %v", err)
	}
}

// TestResolveTargetIsExact pins scope resolution: only a configured scope id
// resolves, and the error names no secret material.
func TestResolveTargetIsExact(t *testing.T) {
	t.Parallel()

	collector := testCollector(t, &fakeVaultClient{})
	if _, err := collector.ResolveTarget("vault_live:test-scope"); err != nil {
		t.Fatalf("ResolveTarget(configured) error = %v", err)
	}
	_, err := collector.ResolveTarget("vault_live:other-scope")
	if err == nil {
		t.Fatal("ResolveTarget(unknown) = nil, want error")
	}
	if strings.Contains(err.Error(), "test-token") {
		t.Fatalf("unknown-scope error leaks the token: %v", err)
	}
}
