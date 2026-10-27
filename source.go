// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-collector-vault-live/document"
)

// Collector is the validated standalone collection source: configured Vault
// targets and the client factory. The SDK handler drives it once per claim.
type Collector struct {
	collectorInstanceID string
	targets             map[string]TargetConfig
	key                 redactionKey
	newClient           func(TargetConfig) (Client, error)
}

// NewCollector validates config and builds a standalone collection source.
func NewCollector(config SourceConfig) (*Collector, error) {
	collectorID := strings.TrimSpace(config.CollectorInstanceID)
	if collectorID == "" {
		return nil, fmt.Errorf("vault live collector instance id is required")
	}
	if config.Key.isZero() {
		return nil, fmt.Errorf("vault live collector redaction key is required")
	}
	if len(config.Targets) == 0 {
		return nil, fmt.Errorf("vault live collector requires at least one target")
	}
	newClient := config.NewClient
	if newClient == nil {
		newClient = defaultVaultClient
	}
	targets := make(map[string]TargetConfig, len(config.Targets))
	for i, target := range config.Targets {
		if strings.TrimSpace(target.VaultClusterID) == "" {
			return nil, fmt.Errorf("target %d: vault_cluster_id must not be blank", i)
		}
		if strings.TrimSpace(target.ScopeID) == "" {
			return nil, fmt.Errorf("target %d: scope_id must not be blank", i)
		}
		if _, dup := targets[target.ScopeID]; dup {
			return nil, fmt.Errorf("target %d: duplicate vault target scope_id %q", i, target.ScopeID)
		}
		targets[target.ScopeID] = target
	}
	return &Collector{
		collectorInstanceID: collectorID,
		targets:             targets,
		key:                 config.Key,
		newClient:           newClient,
	}, nil
}

func defaultVaultClient(target TargetConfig) (Client, error) {
	return newHTTPAdapter(target.Address, target.Token, target.Namespace, nil)
}

// ResolveTarget returns the configured target for scopeID.
func (c *Collector) ResolveTarget(scopeID string) (TargetConfig, error) {
	if target, ok := c.targets[strings.TrimSpace(scopeID)]; ok {
		return target, nil
	}
	return TargetConfig{}, fmt.Errorf(
		"vault live target scope_id %q is not configured for collector instance %q",
		strings.TrimSpace(scopeID),
		c.collectorInstanceID,
	)
}

// Collect reads metadata from the Vault Client for one target and returns
// redacted reported-confidence SDK facts covering all seven Vault metadata
// fact families. It performs no graph writes and never reads a secret value.
//
// Collection is per-family resilient: a single family's list failure (for
// example a permission-scoped read) emits a redacted
// secrets_iam_coverage_warning fact (source_state=partial,
// resource_scope=<family>) and collection continues, so one denied family does
// not lose the whole generation. The partial state is therefore explicit in
// the facts, never silently complete. Context cancellation and a malformed
// observation (a build error) remain fatal.
func (c *Collector) Collect(
	ctx context.Context,
	target TargetConfig,
	boundary Boundary,
) ([]sdk.Fact, time.Time, error) {
	client, err := c.newClient(target)
	if err != nil {
		return nil, time.Time{}, err
	}
	if client == nil {
		return nil, time.Time{}, fmt.Errorf("vault client is required")
	}
	// Sanitize the Vault endpoint URL once: a credential-bearing address
	// (basic-auth userinfo or a token query param) must never reach a fact's
	// SourceRef. Every family and the context use the sanitized form. The
	// target address backs the source URI when no explicit source_uri is
	// configured so the host-required SourceRef URI is never blank.
	uri := sanitizeVaultSourceURI(firstNonBlank(target.SourceURI, target.Address))
	vaultCtx := EnvelopeContext{
		VaultClusterID:      target.VaultClusterID,
		Namespace:           target.Namespace,
		ScopeID:             boundary.ScopeID,
		GenerationID:        boundary.GenerationID,
		CollectorInstanceID: c.collectorInstanceID,
		FencingToken:        boundary.FencingToken,
		ObservedAt:          boundary.ObservedAt,
		SourceURI:           uri,
		SourceSystem:        boundary.SourceSystem,
		Key:                 c.key,
	}
	var facts []sdk.Fact

	if facts, err = collectFamily(ctx, facts, vaultCtx, vaultFamilyAuthMounts,
		func() ([]AuthMount, error) { return client.ListAuthMounts(ctx) },
		func(m AuthMount) (sdk.Fact, error) { return NewAuthMountFact(vaultCtx, m, "") }); err != nil {
		return nil, time.Time{}, err
	}
	if facts, err = collectFamily(ctx, facts, vaultCtx, vaultFamilyAuthRoles,
		func() ([]AuthRole, error) { return client.ListAuthRoles(ctx) },
		func(r AuthRole) (sdk.Fact, error) { return NewAuthRoleFact(vaultCtx, r, "") }); err != nil {
		return nil, time.Time{}, err
	}
	if facts, err = collectFamily(ctx, facts, vaultCtx, vaultFamilyACLPolicies,
		func() ([]ACLPolicy, error) { return client.ListACLPolicies(ctx) },
		func(p ACLPolicy) (sdk.Fact, error) { return NewACLPolicyFact(vaultCtx, p, "") }); err != nil {
		return nil, time.Time{}, err
	}
	if facts, err = collectFamily(ctx, facts, vaultCtx, vaultFamilyIdentityEntities,
		func() ([]IdentityEntity, error) { return client.ListIdentityEntities(ctx) },
		func(e IdentityEntity) (sdk.Fact, error) { return NewIdentityEntityFact(vaultCtx, e, "") }); err != nil {
		return nil, time.Time{}, err
	}
	if facts, err = collectFamily(ctx, facts, vaultCtx, vaultFamilyIdentityAliases,
		func() ([]IdentityAlias, error) { return client.ListIdentityAliases(ctx) },
		func(a IdentityAlias) (sdk.Fact, error) { return NewIdentityAliasFact(vaultCtx, a, "") }); err != nil {
		return nil, time.Time{}, err
	}
	if facts, err = collectFamily(ctx, facts, vaultCtx, vaultFamilyKVMetadata,
		func() ([]KVMetadata, error) { return client.ListKVMetadata(ctx) },
		func(m KVMetadata) (sdk.Fact, error) { return NewKVMetadataFact(vaultCtx, m, "") }); err != nil {
		return nil, time.Time{}, err
	}
	if facts, err = collectFamily(ctx, facts, vaultCtx, vaultFamilySecretEngineMounts,
		func() ([]SecretEngineMount, error) { return client.ListSecretEngineMounts(ctx) },
		func(m SecretEngineMount) (sdk.Fact, error) { return NewSecretEngineMountFact(vaultCtx, m, "") }); err != nil {
		return nil, time.Time{}, err
	}

	return facts, boundary.ObservedAt, nil
}

// collectFamily lists one Vault fact family and maps it to facts. A list
// error emits a redacted secrets_iam_coverage_warning (resource_scope=family)
// and returns it instead of failing the whole generation, except for context
// cancellation, which is fatal. A build (mapping) error is fatal — it signals
// a malformed observation, not a source-coverage gap.
func collectFamily[T any](
	ctx context.Context,
	dst []sdk.Fact,
	vaultCtx EnvelopeContext,
	family string,
	list func() ([]T, error),
	build func(T) (sdk.Fact, error),
) ([]sdk.Fact, error) {
	items, err := list()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("list vault %s: %w", family, ctx.Err())
		}
		warning, werr := NewCoverageWarningFact(vaultCtx, family, "")
		if werr != nil {
			return nil, vaultMappingError{err: fmt.Errorf("build vault %s coverage warning: %w", family, werr)}
		}
		return append(dst, warning), nil
	}
	return collectInto(dst, family, items, build)
}

// vaultMappingError marks a malformed-observation failure as terminal: the
// same input cannot succeed on retry.
type vaultMappingError struct {
	err error
}

func (e vaultMappingError) Error() string { return e.err.Error() }

func (e vaultMappingError) Unwrap() error { return e.err }

// collectInto builds one fact per item via build and appends it to dst,
// wrapping a build error with the fact-family label so a malformed
// observation is diagnosable.
func collectInto[T any](
	dst []sdk.Fact,
	family string,
	items []T,
	build func(T) (sdk.Fact, error),
) ([]sdk.Fact, error) {
	dst = slices.Grow(dst, len(items))
	for _, item := range items {
		fact, err := build(item)
		if err != nil {
			return nil, vaultMappingError{err: fmt.Errorf("build %s fact: %w", family, err)}
		}
		dst = append(dst, fact)
	}
	return dst, nil
}

// hasCoverageWarning reports whether the collected facts include a
// secrets/IAM coverage-warning fact, which marks the generation as covering
// only part of the cluster.
func hasCoverageWarning(facts []sdk.Fact) bool {
	for _, fact := range facts {
		if fact.Kind == document.KindCoverageWarning {
			return true
		}
	}
	return false
}

// sanitizeVaultSourceURI returns a provenance-safe form of a Vault endpoint
// URL with any userinfo, query, and fragment removed, so a credential-bearing
// Vault address (basic-auth userinfo or token query parameters) can never be
// persisted in a fact's SourceRef. It returns "" when the value is not a
// parseable absolute URL, so an unexpected shape is omitted rather than
// leaked.
func sanitizeVaultSourceURI(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	safe := url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: parsed.Path}
	return safe.String()
}
