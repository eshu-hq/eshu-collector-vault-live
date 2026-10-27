// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package collector is the standalone vault-live collector component
// surface: the claim-serving entrypoint and seed installer plus the
// deployment manifest the Eshu component-extension host consumes, embedded
// for the seed installer.
//
// With no arguments (or --sdk-stdio) cmd/collector serves one claim: it reads
// one collector-sdk/v1alpha1 request from stdin, collects the named Vault
// target over the read-only metadata-only Vault HTTPS API, and writes one
// result to stdout. It dispatches on the claim kind with the in-tree
// go/internal/collector/vaultlive admission rules: foreign collector kinds and
// source systems are rejected, the read-only token resolves from the
// environment (never from the claim config), collection is per-family
// resilient, and a partial scope emits a secrets_iam_coverage_warning fact.
// With the seed subcommand it writes its own binary and manifest into a
// directory so an init container can install the component without a shell.
//
// Every emitted fact carries Vault metadata only (mounts, roles, policies,
// identity, KV metadata). KV secret values are never read: the client refuses
// KV /data/ reads, so no code path can wire a secret-value read. Names and
// paths are HMAC-fingerprinted with the deployment-scoped redaction key before
// emission; metric labels are bounded enums only. The collector gets no
// Postgres, graph, queue, lease, workflow, or telemetry handle, and it never
// imports the Eshu core module (boundary_test.go enforces this). The host
// builds the core fact envelope, validates the result, and owns claims and
// commits.
//
// The manifest (manifest.yaml, a ComponentPackage) declares the single
// admitted collector kind (vault_live), the digest-pinned artifact slot, and
// the eight emitted vault fact kinds at their published schema versions.
//
// This repository holds no producer authority until the reviewed cutover
// (eshu-hq/eshu#8869).
package collector
