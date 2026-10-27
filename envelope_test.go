// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"strings"
	"testing"

	sdk "github.com/eshu-hq/eshu-sdk/collector"
)

func mustTestKey(t *testing.T) redactionKey {
	t.Helper()
	key, err := newRedactionKey([]byte("vault-live-test-redaction-key"))
	if err != nil {
		t.Fatalf("newRedactionKey: %v", err)
	}
	return key
}

// TestFactBuildersRedactRawVaultMaterial proves the redaction boundary across
// every Vault fact family: raw mount paths, accessors, role names, policy
// names, ACL rule paths, identity ids/names, KV paths, custom-metadata key
// names, bound ServiceAccount names/namespaces, and the Vault namespace must
// never appear verbatim in any emitted payload, because the builders
// fingerprint them. It scans nested values (slices, maps) so a leak in a
// fingerprint list or the ACL rules slice cannot slip past a top-level scan.
func TestFactBuildersRedactRawVaultMaterial(t *testing.T) {
	t.Parallel()

	sentinels := []string{
		"RAWNAMESPACE-team", "RAWMOUNT-kubernetes/", "RAWACCESSOR-k8s",
		"RAWROLE-payments", "RAWSA-payments", "RAWNS-prod", "RAWPOLICY-read",
		"RAWACLNAME-payments", "RAWACLPATH-secret/metadata/payments",
		"RAWENTID-1", "RAWENTNAME-payments", "RAWALIASID-1", "RAWALIASNAME-payments",
		"RAWKVMOUNT-secret/", "RAWKVPATH-payments/db", "RAWCMK-owner",
		"RAWENGMOUNT-secret/", "RAWENGACC-kv",
	}
	ctx := parityContext(mustTestKey(t))
	ctx.Namespace = "RAWNAMESPACE-team"
	builders := map[string]func() (sdk.Fact, error){
		"mount": func() (sdk.Fact, error) {
			return NewAuthMountFact(ctx, AuthMount{
				Path: "RAWMOUNT-kubernetes/", Accessor: "RAWACCESSOR-k8s", Method: "kubernetes",
			}, "")
		},
		"role": func() (sdk.Fact, error) {
			return NewAuthRoleFact(ctx, AuthRole{
				MountPath: "RAWMOUNT-kubernetes/", RoleName: "RAWROLE-payments", Method: "kubernetes",
				KubernetesClusterID:           "cluster-prod",
				BoundServiceAccountNames:      []string{"RAWSA-payments"},
				BoundServiceAccountNamespaces: []string{"RAWNS-prod"},
				TokenPolicyNames:              []string{"RAWPOLICY-read"},
			}, "")
		},
		"policy": func() (sdk.Fact, error) {
			return NewACLPolicyFact(ctx, ACLPolicy{
				PolicyName: "RAWACLNAME-payments", PolicyHash: "sha256:abc",
				Rules: []ACLRule{{Path: "RAWACLPATH-secret/metadata/payments", Capabilities: []string{"read"}}},
			}, "")
		},
		"entity": func() (sdk.Fact, error) {
			return NewIdentityEntityFact(ctx, IdentityEntity{
				EntityID: "RAWENTID-1", EntityName: "RAWENTNAME-payments", AliasCount: 1,
			}, "")
		},
		"alias": func() (sdk.Fact, error) {
			return NewIdentityAliasFact(ctx, IdentityAlias{
				AliasID: "RAWALIASID-1", EntityID: "RAWENTID-1", MountPath: "RAWMOUNT-kubernetes/",
				MountAccessor: "RAWACCESSOR-k8s", AliasName: "RAWALIASNAME-payments",
			}, "")
		},
		"kv": func() (sdk.Fact, error) {
			return NewKVMetadataFact(ctx, KVMetadata{
				MountPath: "RAWKVMOUNT-secret/", Path: "RAWKVPATH-payments/db",
				CurrentVersion: 3, MaxVersions: 10, CustomMetadataKeys: []string{"RAWCMK-owner"},
			}, "")
		},
		"engine": func() (sdk.Fact, error) {
			return NewSecretEngineMountFact(ctx, SecretEngineMount{
				MountPath: "RAWENGMOUNT-secret/", MountAccessor: "RAWENGACC-kv",
				MountType: "kv-v2", KVVersion: "2",
			}, "")
		},
	}
	for name, build := range builders {
		fact, err := build()
		if err != nil {
			t.Fatalf("%s: error = %v", name, err)
		}
		for key, val := range fact.Payload {
			for _, sentinel := range sentinels {
				if envelopePayloadContains(val, sentinel) {
					t.Fatalf("%s: payload[%q] leaks raw Vault material %q", name, key, sentinel)
				}
			}
		}
	}
}

// envelopePayloadContains reports whether needle appears verbatim in any
// string nested anywhere within v, so a leak in a fingerprint list or the
// ACL rules slice-of-maps cannot evade a top-level-only scan.
func envelopePayloadContains(v any, needle string) bool {
	switch typed := v.(type) {
	case string:
		return strings.Contains(typed, needle)
	case []string:
		for _, s := range typed {
			if strings.Contains(s, needle) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if envelopePayloadContains(item, needle) {
				return true
			}
		}
	case []map[string]any:
		for _, item := range typed {
			if envelopePayloadContains(item, needle) {
				return true
			}
		}
	case map[string]any:
		for _, item := range typed {
			if envelopePayloadContains(item, needle) {
				return true
			}
		}
	}
	return false
}

// TestFactBuildersAdmitCleartextEnums pins the redaction boundary direction:
// low-cardinality enums (auth method, mount type, capabilities) stay
// cleartext, so the sweep above cannot pass by fingerprinting everything.
func TestFactBuildersAdmitCleartextEnums(t *testing.T) {
	t.Parallel()

	ctx := parityContext(mustTestKey(t))
	mount, err := NewAuthMountFact(ctx, AuthMount{Path: "auth/kubernetes", Method: "kubernetes"}, "")
	if err != nil {
		t.Fatalf("NewAuthMountFact() error = %v", err)
	}
	if mount.Payload["auth_method"] != "kubernetes" {
		t.Fatalf("auth_method = %v, want cleartext kubernetes", mount.Payload["auth_method"])
	}
	engine, err := NewSecretEngineMountFact(ctx, SecretEngineMount{
		MountPath: "secret/", MountType: "kv-v2", KVVersion: "2",
	}, "")
	if err != nil {
		t.Fatalf("NewSecretEngineMountFact() error = %v", err)
	}
	if engine.Payload["mount_type"] != "kv-v2" {
		t.Fatalf("mount_type = %v, want cleartext kv-v2", engine.Payload["mount_type"])
	}
	policy, err := NewACLPolicyFact(ctx, ACLPolicy{
		PolicyName: "p", PolicyHash: "sha256:h",
		Rules: []ACLRule{{Path: "secret/data/x", Capabilities: []string{"read", "list", "read"}}},
	}, "")
	if err != nil {
		t.Fatalf("NewACLPolicyFact() error = %v", err)
	}
	rules, ok := policy.Payload["rules"].([]map[string]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("rules = %#v, want one rule payload", policy.Payload["rules"])
	}
	capabilities, ok := rules[0]["capabilities"].([]string)
	if !ok || len(capabilities) != 2 || capabilities[0] != "list" || capabilities[1] != "read" {
		t.Fatalf("capabilities = %#v, want [list read]", rules[0]["capabilities"])
	}
}

// TestFactBuildersRequireIdentityFields pins fail-closed construction: blank
// mount paths, role names, policy names, entity ids, alias ids, KV paths, and
// mount types are rejected rather than fingerprinted into collisions.
func TestFactBuildersRequireIdentityFields(t *testing.T) {
	t.Parallel()

	ctx := parityContext(mustTestKey(t))
	cases := map[string]func() (sdk.Fact, error){
		"mount without method": func() (sdk.Fact, error) {
			return NewAuthMountFact(ctx, AuthMount{Path: "kubernetes/"}, "")
		},
		"mount without path": func() (sdk.Fact, error) {
			return NewAuthMountFact(ctx, AuthMount{Method: "kubernetes"}, "")
		},
		"role without method": func() (sdk.Fact, error) {
			return NewAuthRoleFact(ctx, AuthRole{MountPath: "kubernetes/", RoleName: "r"}, "")
		},
		"role without name": func() (sdk.Fact, error) {
			return NewAuthRoleFact(ctx, AuthRole{MountPath: "kubernetes/", Method: "kubernetes"}, "")
		},
		"policy without name": func() (sdk.Fact, error) {
			return NewACLPolicyFact(ctx, ACLPolicy{}, "")
		},
		"entity without id": func() (sdk.Fact, error) {
			return NewIdentityEntityFact(ctx, IdentityEntity{}, "")
		},
		"alias without id": func() (sdk.Fact, error) {
			return NewIdentityAliasFact(ctx, IdentityAlias{MountPath: "kubernetes/", EntityID: "e"}, "")
		},
		"kv without path": func() (sdk.Fact, error) {
			return NewKVMetadataFact(ctx, KVMetadata{MountPath: "secret/"}, "")
		},
		"engine without type": func() (sdk.Fact, error) {
			return NewSecretEngineMountFact(ctx, SecretEngineMount{MountPath: "secret/"}, "")
		},
		"warning without scope": func() (sdk.Fact, error) {
			return NewCoverageWarningFact(ctx, "", "")
		},
	}
	for name, build := range cases {
		if _, err := build(); err == nil {
			t.Errorf("%s: error = nil, want fail-closed rejection", name)
		}
	}
}

// TestACLPolicyFactKeepsEmptyRulesArray pins that a policy with no parsed
// rules emits an empty non-nil rules array, never null.
func TestACLPolicyFactKeepsEmptyRulesArray(t *testing.T) {
	t.Parallel()

	fact, err := NewACLPolicyFact(parityContext(mustTestKey(t)), ACLPolicy{PolicyName: "p"}, "")
	if err != nil {
		t.Fatalf("NewACLPolicyFact() error = %v", err)
	}
	rules, ok := fact.Payload["rules"].([]map[string]any)
	if !ok {
		t.Fatalf("rules = %#v, want []map[string]any", fact.Payload["rules"])
	}
	if rules == nil {
		t.Fatal("rules = nil, want empty non-nil slice")
	}
	if len(rules) != 0 {
		t.Fatalf("len(rules) = %d, want 0", len(rules))
	}
}

// TestCoverageWarningFactRedactsMessage pins that the warning carries no raw
// message and fingerprints only bounded labels.
func TestCoverageWarningFactRedactsMessage(t *testing.T) {
	t.Parallel()

	fact, err := NewCoverageWarningFact(parityContext(mustTestKey(t)), "kv_metadata", "")
	if err != nil {
		t.Fatalf("NewCoverageWarningFact() error = %v", err)
	}
	if _, ok := fact.Payload["message"]; ok {
		t.Fatalf("warning payload stored raw message: %#v", fact.Payload)
	}
	if fact.Payload["source_state"] != "partial" || fact.Payload["resource_scope"] != "kv_metadata" {
		t.Fatalf("warning payload = %#v, want partial/kv_metadata", fact.Payload)
	}
	if fact.Payload["message_fingerprint"] != "" {
		t.Fatalf("warning payload message_fingerprint = %v, want empty for the omitted message", fact.Payload["message_fingerprint"])
	}
}
