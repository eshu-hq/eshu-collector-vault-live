// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// redactionMarkerPrefix is the keyed-HMAC marker prefix the in-tree redaction
// lane emits. Markers are opaque join keys and fingerprints, never raw values.
const redactionMarkerPrefix = "redacted:hmac-sha256:"

// redactionKey is deployment-scoped secret material used to produce HMAC
// redaction markers for Vault names and paths before fact emission. It is the
// command-local counterpart of runtime.Key: the material is resolved from the
// environment (never from the claim config), copied on construction, and never
// exposed, logged, or emitted.
type redactionKey struct {
	material []byte
}

// newRedactionKey constructs a redaction key from deployment-scoped secret
// material. Blank material is rejected because unkeyed markers are vulnerable
// to offline guessing for low-entropy values.
func newRedactionKey(material []byte) (redactionKey, error) {
	if len(strings.TrimSpace(string(material))) == 0 {
		return redactionKey{}, fmt.Errorf("redaction key material must not be blank")
	}
	copied := make([]byte, len(material))
	copy(copied, material)
	return redactionKey{material: copied}, nil
}

// isZero reports whether the key has no material.
func (k redactionKey) isZero() bool {
	return len(k.material) == 0
}

// marker returns the deterministic non-secret marker for raw under the
// in-tree redaction encoding: HMAC-SHA256 over the length-prefixed domain
// separator, reason, source, and raw bytes. It is byte-identical to the
// in-tree redact.String(raw, reason, source, key).Marker for the same inputs,
// so join keys computed here match the reducer's expectations.
func (k redactionKey) marker(raw, reason, source string) string {
	sum := hmac.New(sha256.New, k.material)
	writeRedactField(sum, []byte("redact.v1"))
	writeRedactField(sum, []byte(normRedactLabel(reason)))
	writeRedactField(sum, []byte(normRedactLabel(source)))
	writeRedactField(sum, []byte(raw))
	return redactionMarkerPrefix + hex.EncodeToString(sum.Sum(nil))
}

func normRedactLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return value
}

func writeRedactField(writer interface {
	Write([]byte) (int, error)
}, value []byte,
) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}

// k8sJoinKey returns the unkeyed join key for one Kubernetes ServiceAccount
// selector (cluster, namespace, name). Unlike Vault value fingerprints it is
// deliberately not HMAC-keyed: it is the cross-lane IAM-Vault join anchor the
// in-tree lane emits as "sha256:" + StableID("SecretsIAMKubernetesFingerprint",
// {kind, parts}), and byte-equality here keeps that join intact.
func k8sJoinKey(clusterID, namespace, name string) string {
	return "sha256:" + StableID("SecretsIAMKubernetesFingerprint", map[string]any{
		"kind": "service_account_join",
		"parts": []string{
			strings.TrimSpace(clusterID),
			strings.TrimSpace(namespace),
			strings.TrimSpace(name),
		},
	})
}
