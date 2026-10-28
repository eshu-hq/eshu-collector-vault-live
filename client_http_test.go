// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdktransport "github.com/eshu-hq/eshu-sdk/collector/transport"
)

// vaultStub is a fake Vault metadata API: routes map request paths to the
// JSON body served with 200, codes maps paths to forced status codes, and
// every request records its token, namespace, and list flag for assertions.
type vaultStub struct {
	t         *testing.T
	routes    map[string]string
	codes     map[string]int
	lastToken string
	lastNS    string
	lastList  map[string]bool
}

func newVaultStub(t *testing.T) *vaultStub {
	t.Helper()
	return &vaultStub{
		t:        t,
		routes:   map[string]string{},
		codes:    map[string]int{},
		lastList: map[string]bool{},
	}
}

func (s *vaultStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.lastToken = r.Header.Get("X-Vault-Token")
		s.lastNS = r.Header.Get("X-Vault-Namespace")
		s.lastList[r.URL.Path] = r.URL.Query().Get("list") == "true"
		if code, ok := s.codes[r.URL.Path]; ok {
			if raw := r.Header.Get("X-Test-Retry-After"); raw != "" {
				w.Header().Set("Retry-After", raw)
			}
			w.WriteHeader(code)
			return
		}
		body, ok := s.routes[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if raw := r.Header.Get("X-Test-Retry-After"); raw != "" {
			w.Header().Set("Retry-After", raw)
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(body)); err != nil {
			s.t.Errorf("stub write: %v", err)
		}
	})
}

// testAdapter wires an httpAdapter to a stub server; the caller seeds routes.
func testAdapter(t *testing.T, stub *vaultStub, namespace string) (*httpAdapter, func()) {
	t.Helper()
	srv := httptest.NewServer(stub.handler())
	a, err := newHTTPAdapter(srv.URL, "test-token", namespace, srv.Client())
	if err != nil {
		t.Fatalf("newHTTPAdapter: %v", err)
	}
	return a, srv.Close
}

func TestNewHTTPAdapterValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		address   string
		token     string
		wantError string
	}{
		{"empty address", "", "tok", "absolute URL"},
		{"no scheme", "vault:8200", "tok", "absolute URL"},
		{"non-http scheme", "ftp://vault:8200", "tok", "scheme"},
		{"empty token", "http://vault:8200", "  ", "token is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := newHTTPAdapter(tc.address, tc.token, "", nil); err == nil ||
				!strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantError)
			}
		})
	}
}

func TestNewHTTPAdapterNormalizes(t *testing.T) {
	t.Parallel()
	a, err := newHTTPAdapter("http://vault:8200/", "  tok  ", "ns/", nil)
	if err != nil {
		t.Fatalf("newHTTPAdapter: %v", err)
	}
	if a.address != "http://vault:8200" || a.token != "tok" || a.namespace != "ns/" {
		t.Fatalf("unexpected normalization: %+v", a)
	}
	if a.httpClient == nil {
		t.Fatal("nil http client should select the SDK default")
	}
}

func TestDoRequestGuards(t *testing.T) {
	t.Parallel()
	a, err := newHTTPAdapter("http://vault:8200", "tok", "", nil)
	if err != nil {
		t.Fatalf("newHTTPAdapter: %v", err)
	}
	ctx := context.Background()
	if _, err := a.doRequest(ctx, "secret/../data/x", false, nil); !errors.Is(err, errForbiddenPathTraversal) {
		t.Fatalf("traversal err = %v", err)
	}
	if _, err := a.doRequest(ctx, "secret/data/x", false, nil); !errors.Is(err, errForbiddenDataPath) {
		t.Fatalf("data-path err = %v", err)
	}
	if got := (vaultAuthError{statusCode: 403}).Error(); !strings.Contains(got, "Forbidden") {
		t.Fatalf("auth error text = %q", got)
	}
	if got := vaultTransportError("op", errors.New("boom")).Error(); !strings.Contains(got, "request failed") {
		t.Fatalf("transport error text = %q", got)
	}
}

func TestDoRequestStatuses(t *testing.T) {
	t.Parallel()
	stub := newVaultStub(t)
	stub.routes["/v1/sys/auth"] = `{"data":{}}`
	stub.codes["/v1/secret/missing"] = http.StatusNotFound
	stub.codes["/v1/secret/denied"] = http.StatusForbidden
	stub.codes["/v1/secret/broken"] = http.StatusInternalServerError
	stub.routes["/v1/secret/garbage"] = `{"data":`
	a, done := testAdapter(t, stub, "team-a")
	defer done()
	ctx := context.Background()

	var payload map[string]any
	ok, err := a.doRequest(ctx, "sys/auth", false, &payload)
	if err != nil || !ok {
		t.Fatalf("ok request: ok=%v err=%v", ok, err)
	}
	if stub.lastToken != "test-token" || stub.lastNS != "team-a" {
		t.Fatalf("token=%q ns=%q", stub.lastToken, stub.lastNS)
	}
	if ok, err := a.doRequest(ctx, "secret/missing", false, &payload); err != nil || ok {
		t.Fatalf("404: ok=%v err=%v", ok, err)
	}
	if _, err := a.doRequest(ctx, "secret/denied", false, &payload); err == nil {
		t.Fatal("403 should fail")
	} else {
		var authErr vaultAuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("403 err type = %T", err)
		}
	}
	if _, err := a.doRequest(ctx, "secret/broken", false, &payload); err == nil {
		t.Fatal("500 should fail")
	} else {
		var httpErr sdktransport.HTTPError
		if !errors.As(err, &httpErr) || httpErr.StatusCode != 500 {
			t.Fatalf("500 err = %v", err)
		}
	}
	if _, err := a.doRequest(ctx, "secret/garbage", false, &payload); err == nil {
		t.Fatal("bad JSON should fail")
	}
	// A dead server surfaces a transport error, never a status.
	dead, err := newHTTPAdapter("http://127.0.0.1:1", "tok", "", nil)
	if err != nil {
		t.Fatalf("newHTTPAdapter: %v", err)
	}
	if _, err := dead.doRequest(ctx, "sys/auth", false, &payload); err == nil {
		t.Fatal("dead server should fail")
	} else {
		var httpErr sdktransport.HTTPError
		if !errors.As(err, &httpErr) || !strings.Contains(httpErr.Message, "request failed") {
			t.Fatalf("transport err = %v", httpErr)
		}
	}
}

func TestListKeysAbsent(t *testing.T) {
	t.Parallel()
	stub := newVaultStub(t)
	a, done := testAdapter(t, stub, "")
	defer done()
	keys, err := a.listKeys(context.Background(), "sys/policies/acl")
	if err != nil || keys != nil {
		t.Fatalf("absent LIST: keys=%v err=%v", keys, err)
	}
}

func TestListMountsViews(t *testing.T) {
	t.Parallel()
	stub := newVaultStub(t)
	stub.routes["/v1/sys/auth"] = `{"data":{
		"kubernetes/": {"type":"kubernetes","accessor":"auth_k8s_1","local":false,
			"config":{"default_lease_ttl":3600,"max_lease_ttl":"24h"},"options":{}},
		"userpass/": {"type":"userpass","accessor":"auth_user_1","local":true,
			"config":{"default_lease_ttl":"1h30m","max_lease_ttl":0},"options":{}}}}`
	stub.routes["/v1/sys/mounts"] = `{"data":{
		"secret/": {"type":"kv","accessor":"kv_1","local":false,
			"config":{"default_lease_ttl":0,"max_lease_ttl":0},"options":{"version":"2"}},
		"transit/": {"type":"transit","accessor":"t_1","local":false,
			"config":{"default_lease_ttl":"bad","max_lease_ttl":null},"options":{}}}}`
	a, done := testAdapter(t, stub, "")
	defer done()
	ctx := context.Background()

	auth, err := a.ListAuthMounts(ctx)
	if err != nil || len(auth) != 2 {
		t.Fatalf("auth mounts: %v %v", auth, err)
	}
	if auth[0].Path != "kubernetes/" || auth[0].Method != "kubernetes" {
		t.Fatalf("sorted first = %+v", auth[0])
	}
	if auth[0].DefaultLeaseTTLSeconds != 3600 || auth[0].MaxLeaseTTLSeconds != 86400 {
		t.Fatalf("ttl parse: %+v", auth[0])
	}
	if auth[1].DefaultLeaseTTLSeconds != 5400 || !auth[1].Local {
		t.Fatalf("duration-string ttl: %+v", auth[1])
	}
	engines, err := a.ListSecretEngineMounts(ctx)
	if err != nil || len(engines) != 2 {
		t.Fatalf("engines: %v %v", engines, err)
	}
	if engines[0].MountPath != "secret/" || engines[0].KVVersion != "2" {
		t.Fatalf("first engine = %+v", engines[0])
	}
	if engines[1].DefaultLeaseTTLSeconds != 0 {
		t.Fatalf("bad ttl should be 0: %+v", engines[1])
	}
	if stub.lastList["/v1/sys/auth"] {
		t.Fatal("mounts read should be a plain GET, not a LIST")
	}
}

func TestListMountsError(t *testing.T) {
	t.Parallel()
	stub := newVaultStub(t)
	stub.codes["/v1/sys/mounts"] = http.StatusInternalServerError
	a, done := testAdapter(t, stub, "")
	defer done()
	if _, err := a.ListSecretEngineMounts(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if _, err := a.ListAuthMounts(context.Background()); err != nil {
		t.Fatalf("empty auth should succeed, got %v", err)
	}
}

func TestListACLPolicies(t *testing.T) {
	t.Parallel()
	stub := newVaultStub(t)
	stub.routes["/v1/sys/policies/acl"] = `{"data":{"keys":["root","gone","dev"]}}`
	stub.routes["/v1/sys/policies/acl/root"] = `{"data":{"name":"root","policy":"path \"*\" { capabilities = [\"read\"] }"}}`
	stub.routes["/v1/sys/policies/acl/dev"] = `{"data":{"name":"dev","policy":""}}`
	a, done := testAdapter(t, stub, "")
	defer done()

	policies, err := a.ListACLPolicies(context.Background())
	if err != nil || len(policies) != 2 {
		t.Fatalf("policies: %v %v", policies, err)
	}
	if policies[1].PolicyName != "root" || !strings.HasPrefix(policies[1].PolicyHash, "sha256:") {
		t.Fatalf("hash = %+v", policies[1])
	}
	if policies[0].PolicyHash != "" {
		t.Fatalf("empty body should hash empty: %+v", policies[0])
	}
	if hashPolicyBody("  ") != "" {
		t.Fatal("blank body should hash empty")
	}
}
