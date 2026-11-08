# Seed and install

The binary is its own installer, so an init container (or you, by
hand) can lay down the component without a shell script.

```bash
collector seed --dest DIR --image-ref ghcr.io/eshu-hq/eshu-collector-vault-live@sha256:<digest>
```

`seed` writes `DIR/collector` (this binary, mode `0755`) and
`DIR/manifest.yaml` (the embedded manifest). Without
`--image-ref`, `COLLECTOR_IMAGE_REF` supplies the reference. An
image can't embed its own digest, so
[manifest.yaml](../../manifest.yaml) in this repo keeps the all-zero
placeholder digest and deployments stamp the real one at seed
time. The image entrypoint is `/usr/local/bin/collector` with
default argument `--sdk-stdio` (see [Dockerfile](../../Dockerfile)).

Image references stay digest-pinned (`@sha256:...`). After a
release, record the published digest as described in
[Release](release.md), then seed activations from that digest.
First run after install? [Getting started](../getting-started/README.md)
has the one-minute version.
