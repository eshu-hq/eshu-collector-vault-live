// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"strings"
	"time"

	sdk "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-collector-vault-live/document"
)

const (
	// providerVault identifies Vault metadata source evidence.
	providerVault = "vault"
	// redactionPolicyVersion identifies the redaction contract for emitted
	// fingerprints.
	redactionPolicyVersion = "secrets_iam_posture_v1"
)

// EnvelopeContext carries source scope, generation, and claim fields for one
// Vault observation. The redaction key is command-local and never serialized.
type EnvelopeContext struct {
	VaultClusterID      string
	Namespace           string
	ScopeID             string
	GenerationID        string
	CollectorInstanceID string
	FencingToken        int64
	ObservedAt          time.Time
	SourceURI           string
	SourceSystem        string
	Key                 redactionKey
}

func validateEnvelopeContext(ctx EnvelopeContext) error {
	switch {
	case strings.TrimSpace(ctx.VaultClusterID) == "":
		return fmt.Errorf("vault observation requires vault_cluster_id")
	case strings.TrimSpace(ctx.ScopeID) == "":
		return fmt.Errorf("vault observation requires scope_id")
	case strings.TrimSpace(ctx.GenerationID) == "":
		return fmt.Errorf("vault observation requires generation_id")
	case strings.TrimSpace(ctx.CollectorInstanceID) == "":
		return fmt.Errorf("vault observation requires collector_instance_id")
	case ctx.FencingToken <= 0:
		return fmt.Errorf("vault observation fencing_token must be positive")
	case ctx.Key.isZero():
		return fmt.Errorf("vault observation requires redaction key")
	default:
		return nil
	}
}

func vaultBasePayload(ctx EnvelopeContext) map[string]any {
	return map[string]any{
		"vault_cluster_id":         strings.TrimSpace(ctx.VaultClusterID),
		"namespace_fingerprint":    ctx.fingerprintValue("namespace", ctx.Namespace),
		"namespace_depth":          vaultPathDepth(ctx.Namespace),
		"provider":                 providerVault,
		"collector_instance_id":    strings.TrimSpace(ctx.CollectorInstanceID),
		"redaction_policy_version": redactionPolicyVersion,
	}
}

// fingerprintValue returns the keyed HMAC fingerprint for one raw value, or ""
// when the value is blank.
func (ctx EnvelopeContext) fingerprintValue(kind, value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return ctx.fingerprintParts(kind, value)
}

// fingerprintParts fingerprints the trimmed parts under a keyed "vault_metadata"
// reason, byte-identical to the in-tree lane for the same key and inputs.
func (ctx EnvelopeContext) fingerprintParts(kind string, parts ...string) string {
	normalized := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized = append(normalized, strings.TrimSpace(part))
	}
	rawIdentity := StableID("SecretsIAMVaultFingerprint", map[string]any{
		"kind":  strings.TrimSpace(kind),
		"parts": normalized,
	})
	return ctx.Key.marker(rawIdentity, "vault_metadata", strings.TrimSpace(kind))
}

func (ctx EnvelopeContext) fingerprintPath(path string) string {
	return ctx.fingerprintValue("path", canonicalVaultPath(path))
}

func (ctx EnvelopeContext) fingerprintMountPath(path string) string {
	return ctx.fingerprintValue("mount_path", canonicalVaultPath(path))
}

func (ctx EnvelopeContext) fingerprintValues(kind string, values []string) []string {
	values = normalizeKeyList(values)
	output := make([]string, 0, len(values))
	for _, value := range values {
		output = append(output, ctx.fingerprintValue(kind, value))
	}
	return output
}

func (ctx EnvelopeContext) mountJoinKey(mountPath string) (string, error) {
	mountPath = canonicalVaultPath(mountPath)
	if mountPath == "" {
		return "", fmt.Errorf("vault mount join requires mount_path")
	}
	return ctx.fingerprintParts("mount_join", ctx.VaultClusterID, ctx.Namespace, mountPath), nil
}

func (ctx EnvelopeContext) roleJoinKey(mountPath, roleName string) (string, error) {
	mountKey, err := ctx.mountJoinKey(mountPath)
	if err != nil {
		return "", err
	}
	roleName = strings.TrimSpace(roleName)
	if roleName == "" {
		return "", fmt.Errorf("vault role join requires role_name")
	}
	return ctx.fingerprintParts("auth_role_join", mountKey, roleName), nil
}

func (ctx EnvelopeContext) policyJoinKey(policyName string) (string, error) {
	policyName = strings.TrimSpace(policyName)
	if policyName == "" {
		return "", fmt.Errorf("vault policy join requires policy_name")
	}
	return ctx.fingerprintParts("policy_join", ctx.VaultClusterID, ctx.Namespace, policyName), nil
}

func (ctx EnvelopeContext) policyJoinKeys(policyNames []string) []string {
	policyNames = normalizeKeyList(policyNames)
	output := make([]string, 0, len(policyNames))
	for _, policyName := range policyNames {
		key, err := ctx.policyJoinKey(policyName)
		if err == nil {
			output = append(output, key)
		}
	}
	return output
}

func (ctx EnvelopeContext) entityJoinKey(entityID string) (string, error) {
	entityID = strings.TrimSpace(entityID)
	if entityID == "" {
		return "", fmt.Errorf("vault identity entity join requires entity_id")
	}
	return ctx.fingerprintParts("entity_join", ctx.VaultClusterID, ctx.Namespace, entityID), nil
}

// boundServiceAccountJoinKeys returns the cross-lane IAM-Vault join anchors
// for exact (non-wildcard) selectors, or nil when no anchor applies.
func (ctx EnvelopeContext) boundServiceAccountJoinKeys(kubernetesClusterID string, namespaces, names []string) []string {
	kubernetesClusterID = strings.TrimSpace(kubernetesClusterID)
	if hasWildcard(namespaces) || hasWildcard(names) {
		return nil
	}
	namespaces = exactSelectorValues(namespaces)
	names = exactSelectorValues(names)
	if kubernetesClusterID == "" || len(namespaces) == 0 || len(names) == 0 {
		return nil
	}
	joinKeys := make([]string, 0, len(namespaces)*len(names))
	for _, namespace := range namespaces {
		for _, name := range names {
			joinKeys = append(joinKeys, k8sJoinKey(kubernetesClusterID, namespace, name))
		}
	}
	return normalizeKeyList(joinKeys)
}

func (ctx EnvelopeContext) policyRulePayloads(rules []ACLRule) []map[string]any {
	if len(rules) == 0 {
		return []map[string]any{}
	}
	output := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		output = append(output, map[string]any{
			"path_fingerprint": ctx.fingerprintPath(rule.Path),
			"path_depth":       vaultPathDepth(rule.Path),
			"capabilities":     normalizeActionList(rule.Capabilities),
		})
	}
	return output
}

func vaultFact(
	ctx EnvelopeContext,
	factKind string,
	stableKey string,
	sourceURI string,
	payload map[string]any,
) sdk.Fact {
	sourceSystem := strings.TrimSpace(ctx.SourceSystem)
	if sourceSystem == "" {
		sourceSystem = CollectorKind
	}
	observedAt := ctx.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	return sdk.Fact{
		Kind:             factKind,
		SchemaVersion:    document.VaultLiveSchemaVersionV1,
		StableKey:        stableKey,
		SourceConfidence: sdk.SourceConfidenceReported,
		ObservedAt:       observedAt.UTC(),
		Payload:          payload,
		SourceRef: sdk.SourceRef{
			SourceSystem: sourceSystem,
			ScopeID:      ctx.ScopeID,
			GenerationID: ctx.GenerationID,
			FactKey:      stableKey,
			URI:          sanitizeVaultSourceURI(firstNonBlank(sourceURI, ctx.SourceURI)),
			RecordID:     stableKey,
		},
	}
}

// NewAuthMountFact builds a vault_auth_mount source fact from metadata.
func NewAuthMountFact(ctx EnvelopeContext, m AuthMount, sourceURI string) (sdk.Fact, error) {
	if err := validateEnvelopeContext(ctx); err != nil {
		return sdk.Fact{}, err
	}
	mountKey, err := ctx.mountJoinKey(m.Path)
	if err != nil {
		return sdk.Fact{}, err
	}
	authMethod := strings.TrimSpace(m.Method)
	if authMethod == "" {
		return sdk.Fact{}, fmt.Errorf("vault auth mount observation requires auth_method")
	}
	stableKey := StableID(document.KindAuthMount, map[string]any{
		"mount_join_key":   mountKey,
		"vault_cluster_id": strings.TrimSpace(ctx.VaultClusterID),
	})
	payload := vaultBasePayload(ctx)
	payload["auth_method"] = authMethod
	payload["mount_join_key"] = mountKey
	payload["mount_path_fingerprint"] = ctx.fingerprintMountPath(m.Path)
	payload["mount_path_depth"] = vaultPathDepth(m.Path)
	payload["mount_accessor_fingerprint"] = ctx.fingerprintValue("mount_accessor", m.Accessor)
	payload["local"] = m.Local
	payload["default_lease_ttl_seconds"] = m.DefaultLeaseTTLSeconds
	payload["max_lease_ttl_seconds"] = m.MaxLeaseTTLSeconds
	return vaultFact(ctx, document.KindAuthMount, stableKey, sourceURI, payload), nil
}

// NewAuthRoleFact builds a vault_auth_role source fact from metadata.
func NewAuthRoleFact(ctx EnvelopeContext, r AuthRole, sourceURI string) (sdk.Fact, error) {
	if err := validateEnvelopeContext(ctx); err != nil {
		return sdk.Fact{}, err
	}
	authMethod := strings.TrimSpace(r.Method)
	if authMethod == "" {
		return sdk.Fact{}, fmt.Errorf("vault auth role observation requires auth_method")
	}
	roleKey, err := ctx.roleJoinKey(r.MountPath, r.RoleName)
	if err != nil {
		return sdk.Fact{}, err
	}
	mountKey, err := ctx.mountJoinKey(r.MountPath)
	if err != nil {
		return sdk.Fact{}, err
	}
	policyKeys := ctx.policyJoinKeys(r.TokenPolicyNames)
	joinKeys := ctx.boundServiceAccountJoinKeys(
		r.KubernetesClusterID,
		r.BoundServiceAccountNamespaces,
		r.BoundServiceAccountNames,
	)
	selectorWildcard := hasWildcard(r.BoundServiceAccountNames) ||
		hasWildcard(r.BoundServiceAccountNamespaces)
	stableKey := StableID(document.KindAuthRole, map[string]any{
		"role_join_key":    roleKey,
		"vault_cluster_id": strings.TrimSpace(ctx.VaultClusterID),
	})
	payload := vaultBasePayload(ctx)
	payload["auth_method"] = authMethod
	payload["mount_join_key"] = mountKey
	payload["role_join_key"] = roleKey
	payload["role_name_fingerprint"] = ctx.fingerprintValue("auth_role", r.RoleName)
	payload["bound_service_account_name_count"] = len(normalizeKeyList(r.BoundServiceAccountNames))
	payload["bound_service_account_namespace_count"] = len(normalizeKeyList(r.BoundServiceAccountNamespaces))
	payload["bound_service_account_name_fingerprints"] = ctx.fingerprintValues("service_account", r.BoundServiceAccountNames)
	payload["bound_service_account_namespace_fingerprints"] = ctx.fingerprintValues("namespace", r.BoundServiceAccountNamespaces)
	if len(joinKeys) > 0 {
		payload["bound_service_account_join_keys"] = joinKeys
	}
	payload["bound_service_account_selector_wildcard"] = selectorWildcard
	payload["token_policy_count"] = len(policyKeys)
	payload["token_policy_join_keys"] = policyKeys
	payload["token_policy_name_fingerprints"] = ctx.fingerprintValues("policy_name", r.TokenPolicyNames)
	payload["token_ttl_seconds"] = r.TokenTTLSeconds
	return vaultFact(ctx, document.KindAuthRole, stableKey, sourceURI, payload), nil
}

// NewACLPolicyFact builds a vault_acl_policy source fact from metadata.
func NewACLPolicyFact(ctx EnvelopeContext, p ACLPolicy, sourceURI string) (sdk.Fact, error) {
	if err := validateEnvelopeContext(ctx); err != nil {
		return sdk.Fact{}, err
	}
	policyKey, err := ctx.policyJoinKey(p.PolicyName)
	if err != nil {
		return sdk.Fact{}, err
	}
	stableKey := StableID(document.KindACLPolicy, map[string]any{
		"policy_join_key":  policyKey,
		"vault_cluster_id": strings.TrimSpace(ctx.VaultClusterID),
	})
	payload := vaultBasePayload(ctx)
	payload["policy_join_key"] = policyKey
	payload["policy_name_fingerprint"] = ctx.fingerprintValue("policy_name", p.PolicyName)
	payload["policy_hash_fingerprint"] = ctx.fingerprintValue("policy_hash", p.PolicyHash)
	payload["rules"] = ctx.policyRulePayloads(p.Rules)
	payload["rule_count"] = len(p.Rules)
	return vaultFact(ctx, document.KindACLPolicy, stableKey, sourceURI, payload), nil
}

// NewIdentityEntityFact builds a vault_identity_entity source fact.
func NewIdentityEntityFact(ctx EnvelopeContext, e IdentityEntity, sourceURI string) (sdk.Fact, error) {
	if err := validateEnvelopeContext(ctx); err != nil {
		return sdk.Fact{}, err
	}
	entityKey, err := ctx.entityJoinKey(e.EntityID)
	if err != nil {
		return sdk.Fact{}, err
	}
	stableKey := StableID(document.KindIdentityEntity, map[string]any{
		"entity_join_key":  entityKey,
		"vault_cluster_id": strings.TrimSpace(ctx.VaultClusterID),
	})
	payload := vaultBasePayload(ctx)
	payload["entity_join_key"] = entityKey
	payload["entity_id_fingerprint"] = ctx.fingerprintValue("entity_id", e.EntityID)
	payload["entity_name_fingerprint"] = ctx.fingerprintValue("entity_name", e.EntityName)
	payload["alias_count"] = e.AliasCount
	payload["group_count"] = e.GroupCount
	payload["disabled"] = e.Disabled
	return vaultFact(ctx, document.KindIdentityEntity, stableKey, sourceURI, payload), nil
}

// NewIdentityAliasFact builds a vault_identity_alias source fact.
func NewIdentityAliasFact(ctx EnvelopeContext, a IdentityAlias, sourceURI string) (sdk.Fact, error) {
	if err := validateEnvelopeContext(ctx); err != nil {
		return sdk.Fact{}, err
	}
	aliasID := strings.TrimSpace(a.AliasID)
	if aliasID == "" {
		return sdk.Fact{}, fmt.Errorf("vault identity alias observation requires alias_id")
	}
	mountKey, err := ctx.mountJoinKey(a.MountPath)
	if err != nil {
		return sdk.Fact{}, err
	}
	entityKey, err := ctx.entityJoinKey(a.EntityID)
	if err != nil {
		return sdk.Fact{}, err
	}
	stableKey := StableID(document.KindIdentityAlias, map[string]any{
		"alias_id":         ctx.fingerprintValue("alias_id", aliasID),
		"vault_cluster_id": strings.TrimSpace(ctx.VaultClusterID),
	})
	payload := vaultBasePayload(ctx)
	payload["alias_id_fingerprint"] = ctx.fingerprintValue("alias_id", aliasID)
	payload["alias_name_fingerprint"] = ctx.fingerprintValue("alias_name", a.AliasName)
	payload["entity_join_key"] = entityKey
	payload["mount_join_key"] = mountKey
	payload["mount_accessor_fingerprint"] = ctx.fingerprintValue("mount_accessor", a.MountAccessor)
	return vaultFact(ctx, document.KindIdentityAlias, stableKey, sourceURI, payload), nil
}

// NewKVMetadataFact builds a vault_kv_metadata source fact from KV v2 metadata.
func NewKVMetadataFact(ctx EnvelopeContext, m KVMetadata, sourceURI string) (sdk.Fact, error) {
	if err := validateEnvelopeContext(ctx); err != nil {
		return sdk.Fact{}, err
	}
	mountKey, err := ctx.mountJoinKey(m.MountPath)
	if err != nil {
		return sdk.Fact{}, err
	}
	pathFingerprint := ctx.fingerprintPath(m.Path)
	if pathFingerprint == "" {
		return sdk.Fact{}, fmt.Errorf("vault kv metadata observation requires path")
	}
	stableKey := StableID(document.KindKVMetadata, map[string]any{
		"kv_path_fingerprint": pathFingerprint,
		"mount_join_key":      mountKey,
		"vault_cluster_id":    strings.TrimSpace(ctx.VaultClusterID),
	})
	payload := vaultBasePayload(ctx)
	payload["mount_join_key"] = mountKey
	payload["mount_path_fingerprint"] = ctx.fingerprintMountPath(m.MountPath)
	payload["kv_path_fingerprint"] = pathFingerprint
	payload["path_depth"] = vaultPathDepth(m.Path)
	payload["current_version"] = m.CurrentVersion
	payload["oldest_version"] = m.OldestVersion
	payload["max_versions"] = m.MaxVersions
	payload["cas_required"] = m.CASRequired
	payload["delete_version_after_seconds"] = m.DeleteVersionAfterSecs
	payload["custom_metadata_key_count"] = len(normalizeKeyList(m.CustomMetadataKeys))
	payload["custom_metadata_key_fingerprints"] = ctx.fingerprintValues("custom_metadata_key", m.CustomMetadataKeys)
	return vaultFact(ctx, document.KindKVMetadata, stableKey, sourceURI, payload), nil
}

// NewSecretEngineMountFact builds a vault_secret_engine_mount source fact.
func NewSecretEngineMountFact(ctx EnvelopeContext, m SecretEngineMount, sourceURI string) (sdk.Fact, error) {
	if err := validateEnvelopeContext(ctx); err != nil {
		return sdk.Fact{}, err
	}
	mountKey, err := ctx.mountJoinKey(m.MountPath)
	if err != nil {
		return sdk.Fact{}, err
	}
	mountType := strings.TrimSpace(m.MountType)
	if mountType == "" {
		return sdk.Fact{}, fmt.Errorf("vault secret engine mount observation requires mount_type")
	}
	stableKey := StableID(document.KindSecretEngineMount, map[string]any{
		"mount_join_key":   mountKey,
		"vault_cluster_id": strings.TrimSpace(ctx.VaultClusterID),
	})
	payload := vaultBasePayload(ctx)
	payload["mount_join_key"] = mountKey
	payload["mount_path_fingerprint"] = ctx.fingerprintMountPath(m.MountPath)
	payload["mount_path_depth"] = vaultPathDepth(m.MountPath)
	payload["mount_accessor_fingerprint"] = ctx.fingerprintValue("mount_accessor", m.MountAccessor)
	payload["mount_type"] = mountType
	payload["kv_version"] = strings.TrimSpace(m.KVVersion)
	payload["local"] = m.Local
	payload["default_lease_ttl_seconds"] = m.DefaultLeaseTTLSeconds
	payload["max_lease_ttl_seconds"] = m.MaxLeaseTTLSeconds
	return vaultFact(ctx, document.KindSecretEngineMount, stableKey, sourceURI, payload), nil
}

// NewCoverageWarningFact builds a secrets_iam_coverage_warning fact for
// partial source reads. The raw Vault error never reaches the payload: only
// the bounded family and error-class labels are recorded.
func NewCoverageWarningFact(ctx EnvelopeContext, resourceScope string, sourceURI string) (sdk.Fact, error) {
	if err := validateEnvelopeContext(ctx); err != nil {
		return sdk.Fact{}, err
	}
	resourceScope = strings.TrimSpace(resourceScope)
	if resourceScope == "" {
		return sdk.Fact{}, fmt.Errorf("vault coverage warning requires resource_scope")
	}
	stableKey := StableID(document.KindCoverageWarning, map[string]any{
		"generation":       strings.TrimSpace(ctx.GenerationID),
		"resource_scope":   resourceScope,
		"source_state":     "partial",
		"vault_cluster_id": strings.TrimSpace(ctx.VaultClusterID),
		"warning_kind":     "partial_family",
	})
	payload := vaultBasePayload(ctx)
	payload["warning_kind"] = "partial_family"
	payload["source_state"] = "partial"
	payload["resource_scope"] = resourceScope
	payload["error_class"] = "list_failed"
	payload["message_present"] = false
	payload["message_fingerprint"] = ctx.fingerprintValue("warning_message", "")
	payload["attribute_count"] = 0
	payload["attribute_key_fingerprints"] = ctx.fingerprintValues("attribute_key", nil)
	return vaultFact(ctx, document.KindCoverageWarning, stableKey, sourceURI, payload), nil
}

func firstNonBlank(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
