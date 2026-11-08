# Concepts

Point this collector at a HashiCorp Vault cluster and it reads how
Vault is set up: auth methods, policies, identities, secret
engines. It turns that setup into facts for Eshu and never reads a
secret value to do it. The host validates and commits; the
collector stores nothing and changes nothing in Vault.

A bit of vocabulary. Vault is a system that stores secrets and
controls who may read them. A *fact* is one small, typed piece of
evidence. A *claim* is one bounded request to collect one Vault
target. The *host* is the Eshu process that starts this collector,
sends it a claim, and stores the result. Evidence here is metadata
only: how Vault is set up, never the secrets it guards.

## When to use it

Use it when Eshu needs evidence about how a Vault cluster is set
up: its auth mounts and roles, ACL policies, identity entities and
aliases, secrets engine mounts, and which KV paths exist.

## When not to use it

- Don't use it to read secret values. That is blocked by design.
- Don't use it to change Vault. It only reads metadata.
- Don't use it as a Vault browser for humans.
  It returns facts to the Eshu host; it has no user interface.
- Don't put a Vault token in config.
  Config with a token key is rejected; use `token_env` instead.

## What you get

The full fact table lives in [Facts](../reference/facts.md), which
mirrors `spec.emittedFacts` in [manifest.yaml](../../manifest.yaml).

ACL means access control list. KV means Vault's key-value secrets
engine.

Two safety properties shape everything here. The client refuses KV
`/data/` reads, so no code path can read a secret value. And names
and paths are fingerprinted with a keyed hash (HMAC, a one-way
fingerprint that needs a secret key) before emission, so facts
carry stable fingerprints instead of raw Vault names.

## Boundaries: what this never does

- It never writes to the Eshu graph, Postgres, or any queue.
  It holds no Postgres, graph, queue, lease, or workflow handle,
  and it never imports the Eshu core module.
- It never reads a KV secret value; `/data/` reads are refused.
- It never emits a raw Vault name or path; fingerprints replace them.
- It never accepts a token from config or logs one.
- It never changes Vault; every API call is a read or list.

For the flow behind these boundaries, see
[Architecture](../architecture/README.md) and
[Diagrams](../diagrams/README.md).
