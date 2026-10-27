// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package document

// Emitted fact-kind vocabulary for the vault-live collector, ported from the
// in-tree go/internal/collector/vaultlive mappers (eshu-hq/eshu#8869). All
// seven source facts are metadata-only; the warning covers partial scope.
const (
	KindAuthMount         = "vault_auth_mount"
	KindAuthRole          = "vault_auth_role"
	KindACLPolicy         = "vault_acl_policy"
	KindIdentityEntity    = "vault_identity_entity"
	KindIdentityAlias     = "vault_identity_alias"
	KindKVMetadata        = "vault_kv_metadata"
	KindSecretEngineMount = "vault_secret_engine_mount"
	// KindCoverageWarning is emitted on partial scope when one namespace or
	// cluster target fails while others succeed.
	KindCoverageWarning = "secrets_iam_coverage_warning"

	// VaultLiveSchemaVersionV1 is the shared schema version for all eight
	// kinds: the core fact-kind registry pins every vault kind (plus the
	// secrets_iam coverage warning) at 1.0.0, and the pinned factschema
	// fixture pack ships the v1 JSON Schema for each.
	VaultLiveSchemaVersionV1 = "1.0.0"
)

// FactKinds lists every fact kind this collector emits, in stable order. It
// is the vocabulary the SDK pin test and the extraction census agree on.
var FactKinds = []string{
	KindAuthMount,
	KindAuthRole,
	KindACLPolicy,
	KindIdentityEntity,
	KindIdentityAlias,
	KindKVMetadata,
	KindSecretEngineMount,
	KindCoverageWarning,
}
