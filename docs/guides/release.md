# Release

```bash
make ci
```

`make ci` runs `make lint`, `make test`, and `make race` (see
[Makefile](../../Makefile)): vet, lint and format checks, module
drift, no `replace` directives, the 500-line file cap, the full
test suite, and the race suite with the coverage floor read from
CI.

Releases: tag `v<manifest version>` on the protected `main` head.
The release workflow refuses a tag on any other commit, publishes
`ghcr.io/eshu-hq/eshu-collector-vault-live` with build-provenance
and SBOM attestations, and reports the digest in the job summary.
Use a `v<manifest version>-*` prerelease tag (for example
`v0.1.0-qa.1`) for QA images. Copy the published digest into the
activation seed reference as shown above; `scripts/pin-digest.sh`
resolves a pushed tag to its digest reference.

Before tagging, run the local gate from
[Contributing](../contributing/README.md) and re-read
[manifest.yaml](../../manifest.yaml): the manifest version, the
git tag, and the pinned image digest must agree.
