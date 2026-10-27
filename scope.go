// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"fmt"
	"sort"
	"strings"
)

// VaultScopeID returns the deterministic durable scope id for one Vault
// cluster and namespace. The namespace is part of the scope identity per the
// in-tree contract ({vault_cluster_id, namespace}): one cluster may host
// multiple namespace targets. The encoding is byte-identical to the in-tree
// VaultScopeID, so claims addressed by the core scheduler resolve here.
func VaultScopeID(clusterID, namespace string) (string, error) {
	clusterID = strings.TrimSpace(clusterID)
	if clusterID == "" {
		return "", fmt.Errorf("vault_cluster_id must not be blank")
	}
	return CollectorKind + ":" + StableID("VaultLiveScope", map[string]any{
		"vault_cluster_id": clusterID,
		"namespace":        strings.TrimSpace(namespace),
	}), nil
}

// authKey is the (cluster, namespace) key shared by config parsing and the
// command-local client factory so the namespace dimension of the scope
// identity is honored end to end. Both dimensions are significant: one
// cluster may host multiple namespace targets with distinct tokens.
func authKey(clusterID, namespace string) string {
	return clusterID + "\x00" + namespace
}

// canonicalVaultPath normalizes equivalent Vault path spellings to one form
// so "auth/kubernetes" and "auth/kubernetes/" share join keys and stable keys.
func canonicalVaultPath(path string) string {
	return strings.Join(vaultPathSegments(path), "/")
}

func vaultPathSegments(path string) []string {
	parts := strings.FieldsFunc(strings.TrimSpace(path), func(r rune) bool {
		return r == '/'
	})
	segments := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			segments = append(segments, part)
		}
	}
	return segments
}

// vaultPathDepth counts the segments of a Vault path ("a/b" is 2, "" is 0).
func vaultPathDepth(path string) int {
	return len(vaultPathSegments(path))
}

// normalizeKeyList trims, drops blanks, dedupes, and sorts values so repeated
// observations produce identical payloads.
func normalizeKeyList(values []string) []string {
	return normalizeStrings(values, nil)
}

// normalizeActionList additionally lowercases capabilities, which Vault
// spells inconsistently across endpoints.
func normalizeActionList(values []string) []string {
	return normalizeStrings(values, strings.ToLower)
}

func normalizeStrings(values []string, mapFn func(string) string) []string {
	seen := make(map[string]struct{}, len(values))
	output := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if mapFn != nil {
			trimmed = mapFn(trimmed)
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		output = append(output, trimmed)
	}
	sort.Strings(output)
	return output
}

// hasWildcard reports whether any selector value carries a glob character.
func hasWildcard(values []string) bool {
	for _, value := range values {
		if strings.ContainsAny(strings.TrimSpace(value), "*?[]") {
			return true
		}
	}
	return false
}

// exactSelectorValues drops wildcard selectors, which cannot anchor a join.
func exactSelectorValues(values []string) []string {
	values = normalizeKeyList(values)
	output := make([]string, 0, len(values))
	for _, value := range values {
		if !hasWildcard([]string{value}) {
			output = append(output, value)
		}
	}
	return output
}
