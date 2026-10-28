// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

package collector

import (
	"context"
	"sort"
	"strings"
	"testing"
)

func seedKVMounts(stub *vaultStub) {
	stub.routes["/v1/sys/mounts"] = `{"data":{
		"secret/": {"type":"kv","accessor":"kv_1","local":false,
			"config":{},"options":{"version":"2"}},
		"legacy/": {"type":"kv","accessor":"kv_2","local":false,
			"config":{},"options":{"version":"1"}},
		"transit/": {"type":"transit","accessor":"t_1","local":false,
			"config":{},"options":{}}}}`
}

func TestListKVMetadataWalk(t *testing.T) {
	t.Parallel()
	stub := newVaultStub(t)
	seedKVMounts(stub)
	stub.routes["/v1/secret/metadata"] = `{"data":{"keys":["app/","gone","top"]}}`
	stub.routes["/v1/secret/metadata/app"] = `{"data":{"keys":["db"]}}`
	stub.routes["/v1/secret/metadata/top"] = `{"data":{
		"current_version":3,"oldest_version":1,"max_versions":5,
		"cas_required":true,"delete_version_after":"1h",
		"custom_metadata":{"team":"sre","owner":"sre"}}}`
	stub.routes["/v1/secret/metadata/app/db"] = `{"data":{
		"current_version":1,"oldest_version":1,"max_versions":0,
		"cas_required":false,"delete_version_after":60,"custom_metadata":{}}}`
	a, done := testAdapter(t, stub, "")
	defer done()

	meta, err := a.ListKVMetadata(context.Background())
	if err != nil || len(meta) != 2 {
		t.Fatalf("metadata: %v %v", meta, err)
	}
	if meta[0].Path != "app/db" || meta[1].Path != "top" {
		t.Fatalf("sorted = %+v", meta)
	}
	top := meta[1]
	if top.MountPath != "secret/" || top.CurrentVersion != 3 || !top.CASRequired {
		t.Fatalf("top = %+v", top)
	}
	if top.DeleteVersionAfterSecs != 3600 {
		t.Fatalf("delete-after = %+v", top)
	}
	if len(top.CustomMetadataKeys) != 2 || !sort.StringsAreSorted(top.CustomMetadataKeys) {
		t.Fatalf("custom keys = %+v", top.CustomMetadataKeys)
	}
	if meta[0].DeleteVersionAfterSecs != 60 || meta[0].CustomMetadataKeys != nil {
		t.Fatalf("db = %+v", meta[0])
	}
}

func TestListKVMetadataErrors(t *testing.T) {
	t.Parallel()
	stub := newVaultStub(t)
	stub.codes["/v1/sys/mounts"] = 500
	a, done := testAdapter(t, stub, "")
	defer done()
	if _, err := a.ListKVMetadata(context.Background()); err == nil {
		t.Fatal("mounts failure should propagate")
	}
}

func TestListKVMetadataListError(t *testing.T) {
	t.Parallel()
	stub := newVaultStub(t)
	seedKVMounts(stub)
	stub.codes["/v1/secret/metadata"] = 500
	a, done := testAdapter(t, stub, "")
	defer done()
	if _, err := a.ListKVMetadata(context.Background()); err == nil {
		t.Fatal("LIST failure should propagate")
	}
}

func TestListKVMetadataReadError(t *testing.T) {
	t.Parallel()
	stub := newVaultStub(t)
	seedKVMounts(stub)
	stub.routes["/v1/secret/metadata"] = `{"data":{"keys":["top"]}}`
	stub.codes["/v1/secret/metadata/top"] = 500
	a, done := testAdapter(t, stub, "")
	defer done()
	if _, err := a.ListKVMetadata(context.Background()); err == nil {
		t.Fatal("read failure should propagate")
	}
}

func TestKVHelpers(t *testing.T) {
	t.Parallel()
	if !isKVV2(SecretEngineMount{MountType: "KV", KVVersion: "2"}) {
		t.Fatal("kv type match should be case-insensitive")
	}
	for _, m := range []SecretEngineMount{
		{MountType: "kv", KVVersion: "1"},
		{MountType: "transit", KVVersion: "2"},
		{MountType: "kv", KVVersion: ""},
	} {
		if isKVV2(m) {
			t.Fatalf("should not be kv-v2: %+v", m)
		}
	}
	if got := pathEscapePath("a b/c"); got != "a%20b/c" {
		t.Fatalf("pathEscapePath = %q", got)
	}
	if boundedMapKeys(nil) != nil || boundedMapKeys(map[string]any{}) != nil {
		t.Fatal("empty custom metadata should yield nil keys")
	}
	big := map[string]any{}
	for i := 0; i < 300; i++ {
		big[string(rune('a'+i%26))+strings.Repeat("x", i/26)] = i
	}
	keys := boundedMapKeys(big)
	if len(keys) != customMetaLimit || !sort.StringsAreSorted(keys) {
		t.Fatalf("capped keys = %d sorted=%v", len(keys), sort.StringsAreSorted(keys))
	}
}
