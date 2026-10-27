// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	sdktransport "github.com/eshu-hq/eshu-sdk/collector/transport"
)

// vaultHTTPTimeout bounds one Vault metadata read.
const vaultHTTPTimeout = 30 * time.Second

// vaultAuthError marks a 403 from Vault: the token lacks the read-only
// policy. It carries no token, address, or path.
type vaultAuthError struct {
	statusCode int
}

func (e vaultAuthError) Error() string {
	return fmt.Sprintf("vault: authentication failed (%s)", http.StatusText(e.statusCode))
}

// httpAdapter is a read-only, metadata-only Vault REST client. It holds the
// short-lived token supplied by the caller; the collector never persists it.
type httpAdapter struct {
	httpClient *http.Client
	address    string
	token      string
	namespace  string
}

// newHTTPAdapter creates a metadata-only Vault adapter. It does not validate
// the token; the first call surfaces an auth error.
func newHTTPAdapter(address, token, namespace string, httpClient *http.Client) (*httpAdapter, error) {
	base, err := url.Parse(strings.TrimSpace(address))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("vault address must be an absolute URL")
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("vault address scheme must be http or https")
	}
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("vault token is required")
	}
	if httpClient == nil {
		httpClient = sdktransport.DefaultHTTPClient(vaultHTTPTimeout)
	}
	return &httpAdapter{
		httpClient: httpClient,
		address:    strings.TrimRight(base.String(), "/"),
		token:      strings.TrimSpace(token),
		namespace:  strings.TrimSpace(namespace),
	}, nil
}

// errForbiddenDataPath is returned if any request would touch a KV data path —
// the in-code guarantee that the adapter never reads a secret value.
var errForbiddenDataPath = fmt.Errorf("vault: refusing to request a KV /data/ path (metadata-only)")

// errForbiddenPathTraversal is returned if a constructed path contains a "."
// or ".." segment, which a Vault-returned key name could otherwise use to
// escape the metadata subtree.
var errForbiddenPathTraversal = fmt.Errorf("vault: refusing a path with a traversal segment")

// doRequest issues one GET against /v1/<path>, optionally as a LIST, and
// decodes the JSON body into out. It rejects any traversal segment and any KV
// data path before the request is made, so a hostile Vault LIST response
// cannot redirect the adapter to a non-metadata or secret-value path.
func (a *httpAdapter) doRequest(ctx context.Context, path string, list bool, out any) (bool, error) {
	clean := strings.TrimLeft(path, "/")
	if hasTraversalSegment(clean) {
		return false, errForbiddenPathTraversal
	}
	if isKVDataPath(clean) {
		return false, errForbiddenDataPath
	}
	endpoint := a.address + "/v1/" + clean
	if list {
		endpoint += "?list=true"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, vaultTransportError("build request", err)
	}
	req.Header.Set("X-Vault-Token", a.token)
	if a.namespace != "" {
		req.Header.Set("X-Vault-Namespace", a.namespace)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return false, vaultTransportError("request", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return false, nil
	case http.StatusForbidden:
		return false, vaultAuthError{statusCode: resp.StatusCode}
	default:
		return false, sdktransport.HTTPError{
			Provider:   "vault",
			StatusCode: resp.StatusCode,
			Message:    http.StatusText(resp.StatusCode),
			RetryAfter: sdktransport.ParseRetryAfterHeader(resp.Header.Get("Retry-After")),
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return false, vaultTransportError("read body", err)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return false, vaultTransportError("decode response", err)
		}
	}
	return true, nil
}

// vaultTransportError wraps a raw HTTP transport failure. It carries no
// token; the address stays inside the wrapped cause, which never reaches
// facts, statuses, or logs (the handler only records the failure class).
func vaultTransportError(_ string, err error) error {
	return sdktransport.HTTPError{Provider: "vault", Message: "request failed", Cause: err}
}

// isKVDataPath reports whether a Vault path addresses a KV secret-data
// operation (which must never be read). It scans segments left to right and
// is positional, not a substring match: a "data" segment seen before any
// "metadata" segment is treated as a KV data operation, while a "metadata"
// segment seen first means any later "data" is just a secret legitimately
// named "data" under .../metadata/... and is allowed.
func isKVDataPath(path string) bool {
	for _, segment := range strings.Split(strings.ToLower(path), "/") {
		switch segment {
		case "metadata":
			return false
		case "data":
			return true
		}
	}
	return false
}

// hasTraversalSegment reports whether any path segment is "." or "..", which
// a Vault-returned key name could use to escape the intended subtree.
// url.PathEscape does not encode dots, so this guard is required in addition
// to per-segment escaping.
func hasTraversalSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// listKeys issues a LIST and returns the child keys, or nil if the path is
// absent.
func (a *httpAdapter) listKeys(ctx context.Context, path string) ([]string, error) {
	var payload struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	ok, err := a.doRequest(ctx, path, true, &payload)
	if err != nil || !ok {
		return nil, err
	}
	return payload.Data.Keys, nil
}

// hashPolicyBody returns a stable hash of a raw policy body so the body
// itself never leaves the adapter.
func hashPolicyBody(body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(body))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// durationSeconds parses a Vault duration that may be a JSON number (seconds)
// or a Go duration string (for example "3h0m0s"), returning whole seconds.
func durationSeconds(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var n float64
	if err := json.Unmarshal(raw, &n); err == nil {
		return int(n)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil {
			return int(d.Seconds())
		}
	}
	return 0
}

// pathEscape escapes a single Vault path segment for use in a request path.
func pathEscape(segment string) string {
	return url.PathEscape(strings.TrimSuffix(segment, "/"))
}

// mountInfo is the shared sys/auth and sys/mounts entry shape.
type mountInfo struct {
	Type     string `json:"type"`
	Accessor string `json:"accessor"`
	Local    bool   `json:"local"`
	Config   struct {
		DefaultLeaseTTL json.RawMessage `json:"default_lease_ttl"`
		MaxLeaseTTL     json.RawMessage `json:"max_lease_ttl"`
	} `json:"config"`
	Options map[string]string `json:"options"`
}

func (a *httpAdapter) listMounts(ctx context.Context, path string) (map[string]mountInfo, error) {
	var payload struct {
		Data map[string]mountInfo `json:"data"`
	}
	if _, err := a.doRequest(ctx, path, false, &payload); err != nil {
		return nil, err
	}
	return payload.Data, nil
}

// ListAuthMounts returns auth method mount metadata from sys/auth.
func (a *httpAdapter) ListAuthMounts(ctx context.Context) ([]AuthMount, error) {
	mounts, err := a.listMounts(ctx, "sys/auth")
	if err != nil {
		return nil, err
	}
	out := make([]AuthMount, 0, len(mounts))
	for path, info := range mounts {
		out = append(out, AuthMount{
			Path: path, Accessor: info.Accessor, Method: info.Type, Local: info.Local,
			DefaultLeaseTTLSeconds: durationSeconds(info.Config.DefaultLeaseTTL),
			MaxLeaseTTLSeconds:     durationSeconds(info.Config.MaxLeaseTTL),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// ListSecretEngineMounts returns secret-engine mount metadata from sys/mounts.
func (a *httpAdapter) ListSecretEngineMounts(ctx context.Context) ([]SecretEngineMount, error) {
	mounts, err := a.listMounts(ctx, "sys/mounts")
	if err != nil {
		return nil, err
	}
	out := make([]SecretEngineMount, 0, len(mounts))
	for path, info := range mounts {
		out = append(out, SecretEngineMount{
			MountPath: path, MountAccessor: info.Accessor, MountType: info.Type, Local: info.Local,
			KVVersion:              info.Options["version"],
			DefaultLeaseTTLSeconds: durationSeconds(info.Config.DefaultLeaseTTL),
			MaxLeaseTTLSeconds:     durationSeconds(info.Config.MaxLeaseTTL),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MountPath < out[j].MountPath })
	return out, nil
}

// ListACLPolicies returns ACL policy metadata. The raw policy body is hashed,
// never stored. Per-rule capability summaries are left empty: parsing the
// Vault ACL HCL/JSON policy grammar is deferred; the policy name plus content
// hash are the emitted posture evidence.
func (a *httpAdapter) ListACLPolicies(ctx context.Context) ([]ACLPolicy, error) {
	names, err := a.listKeys(ctx, "sys/policies/acl")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make([]ACLPolicy, 0, len(names))
	for _, name := range names {
		var payload struct {
			Data struct {
				Name   string `json:"name"`
				Policy string `json:"policy"`
			} `json:"data"`
		}
		ok, err := a.doRequest(ctx, "sys/policies/acl/"+pathEscape(name), false, &payload)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out = append(out, ACLPolicy{PolicyName: name, PolicyHash: hashPolicyBody(payload.Data.Policy)})
	}
	return out, nil
}

// ListAuthRoles returns auth role metadata for Kubernetes auth mounts (the
// IAM-Vault join anchor). Other auth methods are skipped; their role shapes
// do not carry the ServiceAccount selectors the trust chain needs.
func (a *httpAdapter) ListAuthRoles(ctx context.Context) ([]AuthRole, error) {
	mounts, err := a.ListAuthMounts(ctx)
	if err != nil {
		return nil, err
	}
	var out []AuthRole
	for _, mount := range mounts {
		if mount.Method != "kubernetes" {
			continue
		}
		base := "auth/" + strings.TrimRight(mount.Path, "/") + "/role"
		names, err := a.listKeys(ctx, base)
		if err != nil {
			return nil, err
		}
		sort.Strings(names)
		for _, name := range names {
			var payload struct {
				Data struct {
					BoundSANames      []string        `json:"bound_service_account_names"`
					BoundSANamespaces []string        `json:"bound_service_account_namespaces"`
					TokenPolicies     []string        `json:"token_policies"`
					TokenTTL          json.RawMessage `json:"token_ttl"`
				} `json:"data"`
			}
			ok, err := a.doRequest(ctx, base+"/"+pathEscape(name), false, &payload)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			out = append(out, AuthRole{
				MountPath: mount.Path, RoleName: name, Method: mount.Method,
				BoundServiceAccountNames:      payload.Data.BoundSANames,
				BoundServiceAccountNamespaces: payload.Data.BoundSANamespaces,
				TokenPolicyNames:              payload.Data.TokenPolicies,
				TokenTTLSeconds:               durationSeconds(payload.Data.TokenTTL),
			})
		}
	}
	return out, nil
}

// ListIdentityEntities returns identity entity metadata.
func (a *httpAdapter) ListIdentityEntities(ctx context.Context) ([]IdentityEntity, error) {
	ids, err := a.listKeys(ctx, "identity/entity/id")
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	out := make([]IdentityEntity, 0, len(ids))
	for _, id := range ids {
		var payload struct {
			Data struct {
				Name     string   `json:"name"`
				Aliases  []any    `json:"aliases"`
				GroupIDs []string `json:"group_ids"`
				Disabled bool     `json:"disabled"`
			} `json:"data"`
		}
		ok, err := a.doRequest(ctx, "identity/entity/id/"+pathEscape(id), false, &payload)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out = append(out, IdentityEntity{
			EntityID: id, EntityName: payload.Data.Name,
			AliasCount: len(payload.Data.Aliases), GroupCount: len(payload.Data.GroupIDs),
			Disabled: payload.Data.Disabled,
		})
	}
	return out, nil
}

// ListIdentityAliases returns identity alias metadata and mount/entity
// anchors.
func (a *httpAdapter) ListIdentityAliases(ctx context.Context) ([]IdentityAlias, error) {
	ids, err := a.listKeys(ctx, "identity/entity-alias/id")
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	out := make([]IdentityAlias, 0, len(ids))
	for _, id := range ids {
		var payload struct {
			Data struct {
				CanonicalID   string `json:"canonical_id"`
				MountAccessor string `json:"mount_accessor"`
				MountPath     string `json:"mount_path"`
				Name          string `json:"name"`
			} `json:"data"`
		}
		ok, err := a.doRequest(ctx, "identity/entity-alias/id/"+pathEscape(id), false, &payload)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out = append(out, IdentityAlias{
			AliasID: id, EntityID: payload.Data.CanonicalID, MountPath: payload.Data.MountPath,
			MountAccessor: payload.Data.MountAccessor, AliasName: payload.Data.Name,
		})
	}
	return out, nil
}
