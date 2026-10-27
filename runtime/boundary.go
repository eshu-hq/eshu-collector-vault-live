// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package runtime

import (
	"fmt"
	"strings"
)

// CollectorKind is the source-system / scope collector-kind identifier for
// the live Vault metadata collector. It must agree with the in-tree scope
// identity it is extracted from; extraction_census_test.go locks that
// agreement.
const CollectorKind = "vault_live"

// ClusterTarget is one configured Vault collection boundary: a Vault cluster
// and namespace. It carries durable, non-secret identity only; connection
// details and the read-only token live in the command-local client factory,
// never in the scope.
type ClusterTarget struct {
	VaultClusterID string
	Namespace      string
	DisplayName    string
	Environment    string
	FencingToken   int64
	SourceURI      string
}

// Key is deployment-scoped secret material used to produce HMAC redaction
// markers for names and paths before fact emission.
//
// The material is never exposed: there is no accessor, and the zero value
// carries nothing. It is the single permitted exception to the no-secret
// extraction boundary (see Config.RedactionKey); it is never the Vault
// token.
type Key struct {
	material []byte
}

// NewKey constructs a redaction key from deployment-scoped secret material.
//
// The material is copied. Blank key material is rejected because unkeyed
// redaction markers are vulnerable to offline guessing for low-entropy
// values.
func NewKey(material []byte) (Key, error) {
	if len(strings.TrimSpace(string(material))) == 0 {
		return Key{}, fmt.Errorf("redaction key material must not be blank")
	}
	copied := make([]byte, len(material))
	copy(copied, material)
	return Key{material: copied}, nil
}

// IsZero reports whether the key has no material.
func (k Key) IsZero() bool {
	return len(k.material) == 0
}

// Config configures the snapshot source with one or more Vault targets. It
// carries the same non-secret identity as ClusterTarget plus exactly one
// documented exception: the deployment-scoped HMAC redaction key
// (RedactionKey, required for fingerprinting names and paths).
type Config struct {
	CollectorInstanceID string
	RedactionKey        Key
	Targets             []ClusterTarget
}

// validated enforces the fail-closed construction contract: an instance
// identity, at least one target, a non-zero redaction key, and no duplicate
// target scope. An empty target list or blank identity is rejected rather
// than defaulted.
func (c Config) validated() (Config, error) {
	if strings.TrimSpace(c.CollectorInstanceID) == "" {
		return Config{}, fmt.Errorf("vault live collector instance id is required")
	}
	if len(c.Targets) == 0 {
		return Config{}, fmt.Errorf("vault live collector requires at least one target")
	}
	if c.RedactionKey.IsZero() {
		return Config{}, fmt.Errorf("vault live collector redaction key is required")
	}
	seen := make(map[string]struct{}, len(c.Targets))
	for i, target := range c.Targets {
		id := strings.TrimSpace(target.VaultClusterID)
		if id == "" {
			return Config{}, fmt.Errorf("target[%d] vault_cluster_id must not be blank", i)
		}
		key := authKey(id, strings.TrimSpace(target.Namespace))
		if _, dup := seen[key]; dup {
			return Config{}, fmt.Errorf("duplicate vault target scope")
		}
		seen[key] = struct{}{}
	}
	return c, nil
}

// authKey is the (cluster, namespace) key shared by config parsing and the
// command-local client factory so the namespace dimension of the scope
// identity is honored end to end. Both dimensions are significant: one
// cluster may host multiple namespace targets with distinct tokens.
func authKey(clusterID, namespace string) string {
	return clusterID + "\x00" + namespace
}
