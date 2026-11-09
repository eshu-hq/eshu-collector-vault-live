# Operate

## How it gets run

The host runs one claim per process invocation. With no arguments
(or `--sdk-stdio`) the binary reads one `collector-sdk/v1alpha1`
request from stdin and writes one result to stdout.

```bash
go run ./cmd/collector --sdk-stdio < request.json > result.json
```

Installing it first? See [Seed and install](seed-and-install.md).

## What to watch

Each served claim writes one bounded JSON diagnostic line to
stderr with the `event` (`complete`, `failure`, `config_failure`,
or `unknown_scope`), `scope`, `generation`, and `latency_ms`. The
line never carries tokens, Vault addresses, raw Vault paths, or
upstream bodies. The host's process runner keeps only a stderr
byte count, so the line helps local runs and tests more than
production operators.

Exit code `0` means one claim was served, even when the result is
retryable or terminal; non-zero means transport failed (oversize
request, expired deadline, malformed JSON, foreign claim kind, or
usage error). Retryable failures with no upstream `Retry-After`
use a 60-second default backoff. The manifest declares metric
prefix `eshu_dp_vault_live_collector_` as declared only: the
collector emits no metric under this prefix and holds no telemetry
handle.

## Dependencies

| Dependency | Version or contract | Where it's pinned |
|---|---|---|
| `github.com/eshu-hq/eshu-sdk/collector` | `v0.1.0-rc.4` | `go.mod` |
| `github.com/eshu-hq/eshu-sdk/factschema` | `v0.1.0-rc.7` | `go.mod` |
| Host protocol | `collector-sdk/v1alpha1`, `process` adapter | [manifest.yaml](../../manifest.yaml) |
| Eshu core compatibility | `>=0.0.5 <0.2.0` | [manifest.yaml](../../manifest.yaml) |
| Producer identity | `dev.eshu.collector.vault-live`, version `0.1.1` | [manifest.yaml](../../manifest.yaml) |
