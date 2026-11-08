# Getting started

Hi! In about a minute you can watch this collector turn
HashiCorp Vault setup metadata over the HTTPS API into facts for Eshu. It only collects and
returns evidence; the Eshu host validates the result and stores it.
Nothing is stored (or changed) here.

## Run it once

```bash
go run ./cmd/collector --sdk-stdio < request.json > result.json
```

There's no fixture mode here: the host request `config` object is the configuration. Copy the field shapes from [Configuration](../reference/configuration.md) and make sure the token env var and `ESHU_VAULT_LIVE_REDACTION_KEY` are set in the process environment before you run it.

## What just happened?

The host runs one *claim* (one bounded request to collect one scope)
per process invocation: one `collector-sdk/v1alpha1` request on
stdin, one result full of typed *facts* on stdout. Eshu can then
answer which auth methods, policies, identities, and secret engines a Vault cluster has, without ever reading a secret value. The picture and the step-by-step flow live
in [Diagrams](../diagrams/README.md) and
[Architecture](../architecture/README.md).

## Where next?

- Every knob: [Configuration](../reference/configuration.md)
- What comes out: [Facts](../reference/facts.md)
- Day-2 work: [Guides](../guides/README.md)
- New words and boundaries: [Concepts](../concepts/README.md)
