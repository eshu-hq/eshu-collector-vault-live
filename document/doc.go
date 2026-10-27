// Package document owns the extracted vault-live collector's emitted
// fact-kind vocabulary: seven metadata-only source facts plus one coverage
// warning.
//
// Every fact this collector emits carries Vault metadata only (mounts,
// roles, policies, identity, KV metadata). KV secret values are never read:
// the read-only Vault client rejects KV /data/ reads, so no code path can
// wire a secret-value read. Names and paths are HMAC-fingerprinted with the
// deployment-scoped redaction key before emission; metric labels are bounded
// enums only.
//
// This package holds no producer authority until the reviewed cutover
// (eshu-hq/eshu#8869).
package document
