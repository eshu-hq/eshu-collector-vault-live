// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package document

import (
	"testing"
)

// TestFactKindVocabularyIsStable locks the emitted vocabulary: eight kinds,
// no duplicates, no blanks. Adding a kind is a contract change that must
// flow through the SDK pin test, the census record, and review.
func TestFactKindVocabularyIsStable(t *testing.T) {
	t.Parallel()

	if len(FactKinds) != 8 {
		t.Fatalf("FactKinds holds %d kinds, want 8", len(FactKinds))
	}
	seen := make(map[string]struct{}, len(FactKinds))
	for _, kind := range FactKinds {
		if kind == "" {
			t.Fatal("FactKinds holds a blank kind")
		}
		if _, dup := seen[kind]; dup {
			t.Fatalf("FactKinds holds duplicate kind %q", kind)
		}
		seen[kind] = struct{}{}
	}
}
