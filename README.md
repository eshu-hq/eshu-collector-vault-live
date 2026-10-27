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
the claim-serving entrypoint lands in a later lane, so there is no stderr
diagnostic shape to document yet.

## Releasing

Tag `v<manifest version>` to publish the image. Use a `v<manifest
version>-*` prerelease (for example `v0.1.0-qa.1`) for QA images: the release
workflow publishes `ghcr.io/eshu-hq/eshu-collector-vault-live` with
build-provenance and SBOM attestations, and reports the digest in the job
summary. Copy that digest into the activation's seed image reference
(`collector seed --image-ref <repo>@sha256:<digest>`). See
`scripts/pin-digest.sh` for resolving a pushed tag to its digest reference.

No tags are cut from the deployment-contract lane: the image build unblocks
when `cmd/collector` (entrypoint plus seed) lands.
