// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// StableID returns a deterministic identifier for one fact-adjacent payload.
// It hashes the fact type together with the normalized identity map, so the
// same identity yields the same id on every collector run, host, and replay.
// The algorithm is byte-identical to the in-tree facts.StableID the lane was
// extracted from: the same SHA-256 over the same
// {"fact_type": factType, "identity": normalize(identity)} encoding, the same
// UTC RFC3339Nano time normalization, and the same recursive map/slice
// normalization. Parity tests pin golden vectors computed from an independent
// oracle of that encoding.
func StableID(factType string, identity map[string]any) string {
	record := map[string]any{
		"fact_type": factType,
		"identity":  normalizeStableValue(identity),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		panic(fmt.Sprintf("marshal stable id payload: %v", err))
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func normalizeStableValue(value any) any {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC().Format(time.RFC3339Nano)
	case map[string]any:
		cloned := make(map[string]any, len(typed))
		for key, nested := range typed {
			cloned[key] = normalizeStableValue(nested)
		}
		return cloned
	case []any:
		cloned := make([]any, len(typed))
		for i := range typed {
			cloned[i] = normalizeStableValue(typed[i])
		}
		return cloned
	case []string:
		cloned := make([]any, len(typed))
		for i := range typed {
			cloned[i] = typed[i]
		}
		return cloned
	default:
		return typed
	}
}
