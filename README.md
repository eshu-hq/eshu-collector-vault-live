# eshu-collector-vault-live

Eshu vault-live collector, extracted from the Eshu core repository.

**Pre-release. Holds no producer authority until its reviewed cutover
(eshu-hq/eshu#8869).**

Extraction tracking: [eshu-hq/eshu#8869](https://github.com/eshu-hq/eshu/issues/8869).
The in-tree extraction census, producer-grant draft, and parity proofs live
in the core repository until the cutover rehearsal lands them here.

## Operator signals

The collector declares the `eshu_dp_vault_live_collector_` metric prefix
(manifest.yaml `spec.telemetry.metricsPrefix`) but emits nothing under it:
it is a stateless claim servant with no OTLP handle.

Each served claim writes one bounded JSON diagnostic line to stderr with the
`event` (`complete`, `failure`, `config_failure`, `unknown_scope`), the
`scope`, `generation`, and `latency_ms` fields; it never carries tokens,
Vault addresses, raw Vault paths, or upstream bodies. The extension host's
process runner does not surface stderr (it keeps only a byte count), so the
line helps a local run and a test, not an operator in production.

Exit codes: `0` serves one claim (a retryable or terminal SDK result is still
a served claim); non-zero means the transport failed (oversize request,
expired deadline, malformed JSON, foreign claim kind, or a usage error).

## Releasing

Tag `v<manifest version>` to publish the image. Use a `v<manifest
version>-*` prerelease (for example `v0.1.0-qa.1`) for QA images: the release
workflow publishes `ghcr.io/eshu-hq/eshu-collector-vault-live` with
build-provenance and SBOM attestations, and reports the digest in the job
summary. Copy that digest into the activation's seed image reference
(`collector seed --image-ref <repo>@sha256:<digest>`). See
`scripts/pin-digest.sh` for resolving a pushed tag to its digest reference.

Seed the component home with `collector seed --dest DIR`, which writes
`DIR/collector` (this binary, mode 0755) and `DIR/manifest.yaml` (the
embedded manifest). Stamp the deployed digest with `collector seed --dest
DIR --image-ref <repo>@sha256:<digest>` (or `COLLECTOR_IMAGE_REF`); the
image cannot embed its own digest, so the repository manifest permanently
carries the all-zero placeholder digest instead.
