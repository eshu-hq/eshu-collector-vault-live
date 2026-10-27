// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"

	sdk "github.com/eshu-hq/eshu-sdk/collector"

	"github.com/eshu-hq/eshu-collector-vault-live/document"
	"github.com/eshu-hq/eshu-collector-vault-live/runtime"
)

const (
	// ComponentID is the manifest identity of this collector. Keep it in sync
	// with metadata.id in manifest.yaml.
	ComponentID = "dev.eshu.collector.vault-live"
	// CollectorKind is the durable collector family name for live Vault
	// metadata facts. It agrees with the in-tree scope identity the lane was
	// extracted from (runtime.CollectorKind, locked by the extraction census).
	CollectorKind = runtime.CollectorKind
	// SourceSystem is the source system name facts carry when the claim does
	// not name one. Hosted claims carry the activation's source system.
	SourceSystem = runtime.CollectorKind
	// MetricsPrefix is the component-owned metric prefix the manifest declares.
	// Nothing in this repository emits a metric under it: the collector is a
	// stateless claim servant with no OTLP handle.
	MetricsPrefix = "eshu_dp_vault_live_collector_"
	// SchemaVersion is the schema version of every emitted vault fact.
	SchemaVersion = document.VaultLiveSchemaVersionV1
)

// SchemaVersionFor returns the schema version for a vault-live fact kind.
func SchemaVersionFor(factKind string) (string, bool) {
	for _, kind := range document.FactKinds {
		if kind == factKind {
			return SchemaVersion, true
		}
	}
	return "", false
}

// ValidateSchemaVersion admits only the supported schema version for a known
// vault-live fact kind, mirroring the host admission hook: unknown kinds and
// incompatible versions fail closed.
func ValidateSchemaVersion(factKind, candidate string) error {
	version, ok := SchemaVersionFor(factKind)
	if !ok {
		return fmt.Errorf("fact kind %q is not a vault live kind", factKind)
	}
	if candidate != version {
		return fmt.Errorf(
			"fact kind %q schema_version %q is unsupported; collector supports %q",
			factKind,
			candidate,
			version,
		)
	}
	return nil
}

// Contract returns the SDK fact families this collector may emit, in manifest
// order.
func Contract() sdk.Contract {
	facts := make([]sdk.FactDeclaration, 0, len(document.FactKinds))
	for _, kind := range document.FactKinds {
		facts = append(facts, sdk.FactDeclaration{
			Kind:             kind,
			SchemaVersions:   []string{SchemaVersion},
			SourceConfidence: []sdk.SourceConfidence{sdk.SourceConfidenceReported},
		})
	}
	return sdk.Contract{ProtocolVersion: sdk.ProtocolVersionV1Alpha1, Facts: facts}
}
