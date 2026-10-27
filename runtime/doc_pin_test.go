// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package runtime

import (
	"testing"

	sdkcollector "github.com/eshu-hq/eshu-sdk/collector"
	"github.com/eshu-hq/eshu-sdk/factschema/fixturepack"
)

// TestSDKPinsResolve proves the module builds against the exact published
// pins with no replace directives, and that the pinned fixture pack ships
// schemas for every fact kind this collector emits.
func TestSDKPinsResolve(t *testing.T) {
	t.Parallel()

	var _ sdkcollector.ResultState = sdkcollector.ResultState("complete")
	for _, kind := range []string{
		"vault_auth_mount",
		"vault_auth_role",
		"vault_acl_policy",
		"vault_identity_entity",
		"vault_identity_alias",
		"vault_kv_metadata",
		"vault_secret_engine_mount",
		"secrets_iam_coverage_warning",
	} {
		schema, ok := fixturepack.SchemaFor(kind)
		if !ok {
			t.Fatalf("pinned fixture pack ships no schema for %q", kind)
		}
		if len(schema) == 0 {
			t.Fatalf("pinned fixture pack ships empty schema for %q", kind)
		}
	}
}
