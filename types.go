// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"time"
)

// Vault metadata views. Every struct carries metadata only: no secret value,
// token, or credential material. The Client surface is metadata-only by
// construction: there is deliberately no method that reads a KV /data/ value,
// a token, or any other secret material. New methods added here must preserve
// that invariant — list and describe metadata only, never read values. The
// source test TestClientSurfaceIsMetadataOnly guards it structurally.
type (
	// AuthMount is the metadata-only view of one Vault auth method mount.
	AuthMount struct {
		Path                   string
		Accessor               string
		Method                 string
		Local                  bool
		DefaultLeaseTTLSeconds int
		MaxLeaseTTLSeconds     int
	}

	// AuthRole is the metadata-only view of one Vault auth role. For
	// Kubernetes auth it carries the bound ServiceAccount selectors that
	// anchor the IAM-Vault join; it never carries a token or JWT.
	AuthRole struct {
		MountPath                     string
		RoleName                      string
		Method                        string
		KubernetesClusterID           string
		BoundServiceAccountNames      []string
		BoundServiceAccountNamespaces []string
		TokenPolicyNames              []string
		TokenTTLSeconds               int
	}

	// ACLRule is one metadata-only Vault ACL rule: a path and its
	// capabilities. The path is fingerprinted downstream; the raw path text
	// never leaves this lane.
	ACLRule struct {
		Path         string
		Capabilities []string
	}

	// ACLPolicy is the metadata-only view of one Vault ACL policy. It carries
	// a policy name plus content hash plus per-rule capability summaries,
	// never the raw policy body.
	ACLPolicy struct {
		PolicyName string
		PolicyHash string
		Rules      []ACLRule
	}

	// IdentityEntity is the metadata-only view of one Vault identity entity.
	IdentityEntity struct {
		EntityID   string
		EntityName string
		AliasCount int
		GroupCount int
		Disabled   bool
	}

	// IdentityAlias is the metadata-only view of one Vault identity alias and
	// its mount/entity join anchors.
	IdentityAlias struct {
		AliasID       string
		EntityID      string
		MountPath     string
		MountAccessor string
		AliasName     string
	}

	// KVMetadata is the metadata-only view of one Vault KV v2 metadata path.
	// It is sourced from the KV v2 metadata endpoint only — never /data/ —
	// and carries version counters and custom-metadata key names, never
	// values or secret data.
	KVMetadata struct {
		MountPath              string
		Path                   string
		CurrentVersion         int
		OldestVersion          int
		MaxVersions            int
		CASRequired            bool
		DeleteVersionAfterSecs int
		CustomMetadataKeys     []string
	}

	// SecretEngineMount is the metadata-only view of one Vault secret-engine
	// mount.
	SecretEngineMount struct {
		MountPath              string
		MountAccessor          string
		MountType              string
		KVVersion              string
		Local                  bool
		DefaultLeaseTTLSeconds int
		MaxLeaseTTLSeconds     int
	}
)

// Client is the narrow, read-only Vault metadata surface the source lane
// needs. The HTTP adapter implements it with the per-target token resolved
// from the environment; tests stub it.
type Client interface {
	ListAuthMounts(ctx context.Context) ([]AuthMount, error)
	ListAuthRoles(ctx context.Context) ([]AuthRole, error)
	ListACLPolicies(ctx context.Context) ([]ACLPolicy, error)
	ListIdentityEntities(ctx context.Context) ([]IdentityEntity, error)
	ListIdentityAliases(ctx context.Context) ([]IdentityAlias, error)
	ListKVMetadata(ctx context.Context) ([]KVMetadata, error)
	ListSecretEngineMounts(ctx context.Context) ([]SecretEngineMount, error)
}

// TargetConfig describes one bounded Vault collection target: a single Vault
// cluster and namespace under a coordinator-assigned claim scope. It carries
// durable, non-secret identity plus the command-local connection settings
// (resolved from the environment, never from the claim).
type TargetConfig struct {
	VaultClusterID string
	Namespace      string
	DisplayName    string
	Environment    string
	SourceURI      string
	ScopeID        string
	Address        string
	Token          string
}

// SourceConfig configures the standalone collection source.
type SourceConfig struct {
	CollectorInstanceID string
	Targets             []TargetConfig
	// Key is the deployment-scoped HMAC redaction key. It is resolved from
	// the environment by ParseSettings, never from the claim config.
	Key redactionKey
	// NewClient builds the Vault client for one target. Nil selects the
	// HTTP adapter. Tests stub it to inject a fake without HTTP.
	NewClient func(TargetConfig) (Client, error)
	// Now supplies the clock; nil selects time.Now.
	Now func() time.Time
}

// Boundary carries the SDK claim identity copied into emitted facts.
type Boundary struct {
	ScopeID             string
	GenerationID        string
	CollectorInstanceID string
	FencingToken        int64
	ObservedAt          time.Time
	// SourceSystem scopes provenance to the claim's source system, which the
	// host requires to match the claim.
	SourceSystem string
}

// Vault fact-family identifiers. They are the bounded resource_scope labels
// for coverage warnings — never a path or secret.
const (
	vaultFamilyAuthMounts         = "auth_mounts"
	vaultFamilyAuthRoles          = "auth_roles"
	vaultFamilyACLPolicies        = "acl_policies"
	vaultFamilyIdentityEntities   = "identity_entities"
	vaultFamilyIdentityAliases    = "identity_aliases"
	vaultFamilyKVMetadata         = "kv_metadata"
	vaultFamilySecretEngineMounts = "secret_engine_mounts"
)
