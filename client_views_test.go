// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestListAuthRoles(t *testing.T) {
	t.Parallel()
	stub := newVaultStub(t)
	stub.routes["/v1/sys/auth"] = `{"data":{
		"kubernetes/": {"type":"kubernetes","accessor":"a1","local":false,"config":{},"options":{}},
		"userpass/": {"type":"userpass","accessor":"a2","local":true,"config":{},"options":{}}}}`
	stub.routes["/v1/auth/kubernetes/role"] = `{"data":{"keys":["reader","gone"]}}`
	stub.routes["/v1/auth/kubernetes/role/reader"] = `{"data":{
		"bound_service_account_names":["vault-reader"],
		"bound_service_account_namespaces":["prod"],
		"token_policies":["dev","ops"],"token_ttl":7200}}`
	a, done := testAdapter(t, stub, "")
	defer done()

	roles, err := a.ListAuthRoles(context.Background())
	if err != nil || len(roles) != 1 {
		t.Fatalf("roles: %v %v", roles, err)
	}
	got := roles[0]
	if got.MountPath != "kubernetes/" || got.RoleName != "reader" || got.Method != "kubernetes" {
		t.Fatalf("role = %+v", got)
	}
	if len(got.BoundServiceAccountNames) != 1 || len(got.BoundServiceAccountNamespaces) != 1 {
		t.Fatalf("selectors = %+v", got)
	}
	if len(got.TokenPolicyNames) != 2 || got.TokenTTLSeconds != 7200 {
		t.Fatalf("token = %+v", got)
	}
}

func TestListAuthRolesSkipsNonKubernetes(t *testing.T) {
	t.Parallel()
	stub := newVaultStub(t)
	stub.routes["/v1/sys/auth"] = `{"data":{
		"userpass/": {"type":"userpass","accessor":"a2","local":true,"config":{},"options":{}}}}`
	a, done := testAdapter(t, stub, "")
	defer done()
	roles, err := a.ListAuthRoles(context.Background())
	if err != nil || len(roles) != 0 {
		t.Fatalf("roles: %v %v", roles, err)
	}
}

func TestListIdentityViews(t *testing.T) {
	t.Parallel()
	stub := newVaultStub(t)
	stub.routes["/v1/identity/entity/id"] = `{"data":{"keys":["e1"]}}`
	stub.routes["/v1/identity/entity/id/e1"] = `{"data":{
		"name":"svc","aliases":[{},{"x":1}],"group_ids":["g1","g2"],"disabled":true}}`
	stub.routes["/v1/identity/entity-alias/id"] = `{"data":{"keys":["a1"]}}`
	stub.routes["/v1/identity/entity-alias/id/a1"] = `{"data":{
		"canonical_id":"e1","mount_accessor":"auth_k8s_1",
		"mount_path":"kubernetes/","name":"system:svc"}}`
	a, done := testAdapter(t, stub, "")
	defer done()
	ctx := context.Background()

	entities, err := a.ListIdentityEntities(ctx)
	if err != nil || len(entities) != 1 {
		t.Fatalf("entities: %v %v", entities, err)
	}
	if entities[0].EntityID != "e1" || entities[0].AliasCount != 2 ||
		entities[0].GroupCount != 2 || !entities[0].Disabled {
		t.Fatalf("entity = %+v", entities[0])
	}
	aliases, err := a.ListIdentityAliases(ctx)
	if err != nil || len(aliases) != 1 {
		t.Fatalf("aliases: %v %v", aliases, err)
	}
	if aliases[0].EntityID != "e1" || aliases[0].MountPath != "kubernetes/" ||
		aliases[0].AliasName != "system:svc" {
		t.Fatalf("alias = %+v", aliases[0])
	}
}

func TestPathHelpers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		path string
		isKV bool
		trav bool
	}{
		{"secret/metadata/app", false, false},
		{"secret/data/app", true, false},
		{"secret/metadata/data", false, false},
		{"ns/secret/DATA/x", true, false},
		{"a/../b", false, true},
		{"a/./b", false, true},
		{"a/.../b", false, false},
		{"plain", false, false},
	} {
		if got := isKVDataPath(tc.path); got != tc.isKV {
			t.Errorf("isKVDataPath(%q) = %v, want %v", tc.path, got, tc.isKV)
		}
		if got := hasTraversalSegment(tc.path); got != tc.trav {
			t.Errorf("hasTraversalSegment(%q) = %v, want %v", tc.path, got, tc.trav)
		}
	}
	if got := pathEscape("a b/"); got != "a%20b" {
		t.Fatalf("pathEscape = %q", got)
	}
}

func TestListViewsPropagateErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	stub := newVaultStub(t)
	for _, p := range []string{
		"/v1/sys/auth", "/v1/sys/mounts", "/v1/sys/policies/acl",
		"/v1/identity/entity/id", "/v1/identity/entity-alias/id",
	} {
		stub.codes[p] = 500
	}
	a, done := testAdapter(t, stub, "")
	defer done()
	// Each view must surface its endpoint failure rather than empty success.
	if _, err := a.ListAuthMounts(ctx); err == nil {
		t.Error("auth mounts: expected error")
	}
	if _, err := a.ListSecretEngineMounts(ctx); err == nil {
		t.Error("engines: expected error")
	}
	if _, err := a.ListACLPolicies(ctx); err == nil {
		t.Error("policies: expected error")
	}
	if _, err := a.ListAuthRoles(ctx); err == nil {
		t.Error("roles: expected error")
	}
	if _, err := a.ListIdentityEntities(ctx); err == nil {
		t.Error("entities: expected error")
	}
	if _, err := a.ListIdentityAliases(ctx); err == nil {
		t.Error("aliases: expected error")
	}
	if _, err := a.ListKVMetadata(ctx); err == nil {
		t.Error("kv metadata: expected error")
	}
}

func TestListNestedReadsPropagateErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	stub := newVaultStub(t)
	stub.routes["/v1/sys/auth"] = `{"data":{
		"kubernetes/": {"type":"kubernetes","accessor":"a1","local":false,"config":{},"options":{}}}}`
	stub.routes["/v1/auth/kubernetes/role"] = `{"data":{"keys":["reader"]}}`
	stub.codes["/v1/auth/kubernetes/role/reader"] = 500
	stub.routes["/v1/identity/entity/id"] = `{"data":{"keys":["e1"]}}`
	stub.codes["/v1/identity/entity/id/e1"] = 500
	stub.routes["/v1/identity/entity-alias/id"] = `{"data":{"keys":["a1"]}}`
	stub.codes["/v1/identity/entity-alias/id/a1"] = 500
	a, done := testAdapter(t, stub, "")
	defer done()

	if _, err := a.ListAuthRoles(ctx); err == nil {
		t.Error("role read: expected error")
	}
	if _, err := a.ListIdentityEntities(ctx); err == nil {
		t.Error("entity read: expected error")
	}
	if _, err := a.ListIdentityAliases(ctx); err == nil {
		t.Error("alias read: expected error")
	}
}

func TestDurationSeconds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw  string
		want int
	}{
		{``, 0},
		{`3600`, 3600},
		{`1.9`, 1},
		{`"2h"`, 7200},
		{`" 90s "`, 90},
		{`"forever"`, 0},
		{`{}`, 0},
		{`null`, 0},
	}
	for _, tc := range cases {
		if got := durationSeconds(json.RawMessage(tc.raw)); got != tc.want {
			t.Errorf("durationSeconds(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestHashPolicyBodyStable(t *testing.T) {
	t.Parallel()
	a, b := hashPolicyBody("policy"), hashPolicyBody("policy")
	if a == "" || a != b || !strings.HasPrefix(a, "sha256:") {
		t.Fatalf("hash = %q", a)
	}
	if hashPolicyBody("other") == a {
		t.Fatal("different bodies must hash differently")
	}
}
