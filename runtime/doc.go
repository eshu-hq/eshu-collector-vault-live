// Package runtime owns the extracted vault-live collector's extraction
// boundary: the scope identity, the cross-boundary target and config types,
// and the deployment-scoped redaction-key handle.
//
// The boundary contract, ported from the in-tree
// go/internal/collector/vaultlive census (eshu-hq/eshu#8869), is that no
// secret material crosses from the command into this package except the
// single documented exception, Config.RedactionKey. Connection details and
// the read-only Vault token stay in the command-local client factory, keyed
// by authKey(cluster, namespace).
//
// This package holds no producer authority until the reviewed cutover
// (eshu-hq/eshu#8869).
package runtime
