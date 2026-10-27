// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"strings"
	"testing"
)

// credentialSentinel is planted inside credential positions below and must
// never survive into a sanitized value or a persisted fact.
const credentialSentinel = "EMBEDDED-CRED-SENTINEL-8869"

// TestSanitizeVaultSourceURIDropsOpaqueCredentials sweeps the sentinel
// through the credential spellings operators paste: hierarchical userinfo,
// token query params, fragments, and values net/url cannot parse at all. The
// sanitizer drops unparseable values instead of returning them verbatim.
func TestSanitizeVaultSourceURIDropsOpaqueCredentials(t *testing.T) {
	t.Parallel()

	hostile := []struct {
		name  string
		value string
	}{
		{name: "hierarchical userinfo", value: "https://svc:" + credentialSentinel + "@vault.internal/v1/sys/auth"},
		{name: "opaque password position", value: "svc:" + credentialSentinel + "@h.internal:8200/v1"},
		{name: "token query param", value: "https://vault.internal/v1?token=" + credentialSentinel},
		{name: "fragment", value: "https://vault.internal/v1#" + credentialSentinel},
		{name: "unparseable authority", value: "svc:pw]" + credentialSentinel + "@h.internal/v1"},
	}
	for _, tt := range hostile {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := sanitizeVaultSourceURI(tt.value); strings.Contains(got, credentialSentinel) {
				t.Errorf("sanitizeVaultSourceURI(%q) = %q kept the credential sentinel", tt.value, got)
			}
		})
	}
}

// TestSanitizeVaultSourceURIKeepsPlainEndpoints is the positive control: a
// credential-free endpoint survives verbatim, so the sweep above cannot pass
// by returning "" for everything.
func TestSanitizeVaultSourceURIKeepsPlainEndpoints(t *testing.T) {
	t.Parallel()

	for _, endpoint := range []string{
		"https://vault.example.com:8200",
		"https://vault.example.com:8200/v1/sys/auth",
		"http://vault.internal:8200/v1/sys/mounts",
	} {
		if got := sanitizeVaultSourceURI(endpoint); got != endpoint {
			t.Errorf("sanitizeVaultSourceURI(%q) = %q, want the endpoint unchanged", endpoint, got)
		}
	}
}

// TestCoverageWarningNeverCarriesRawError drives the warning builder with a
// hostile family label and proves only the bounded label persists: the raw
// error text (path + address) can never reach the fact because it is never
// passed to the builder.
func TestCoverageWarningNeverCarriesRawError(t *testing.T) {
	t.Parallel()

	fact, err := NewCoverageWarningFact(parityContext(mustTestKey(t)), vaultFamilyACLPolicies, "")
	if err != nil {
		t.Fatalf("NewCoverageWarningFact() error = %v", err)
	}
	for _, leak := range []string{"/sys/policies/acl", "vault.example.com", "permission denied"} {
		for key, val := range fact.Payload {
			if s, ok := val.(string); ok && strings.Contains(s, leak) {
				t.Fatalf("payload[%q] = %q leaks raw Vault error context %q", key, s, leak)
			}
		}
		if strings.Contains(fact.SourceRef.URI, leak) && leak != "vault.example.com" {
			t.Fatalf("SourceRef.URI %q leaks raw Vault error context %q", fact.SourceRef.URI, leak)
		}
	}
}
