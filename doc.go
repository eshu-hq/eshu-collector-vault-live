// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 eshu-hq

// Package collector is the standalone vault-live collector component
// surface: the deployment manifest the Eshu component-extension host
// consumes, embedded for the seed installer.
//
// The manifest (manifest.yaml, a ComponentPackage) declares the single
// admitted collector kind (vault_live), the digest-pinned artifact slot,
// and the eight emitted vault fact kinds at their published schema
// versions. The claim-serving entrypoint and the seed subcommand land in a
// later lane; until then the Dockerfile and release workflow describe the
// proven sibling image contract without an image build behind them.
//
// This repository holds no producer authority until the reviewed cutover
// (eshu-hq/eshu#8869).
package collector
