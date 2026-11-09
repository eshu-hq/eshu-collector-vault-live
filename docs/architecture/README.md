# Architecture

Short version: the Eshu host hands this collector one bounded scope,
the collector reads it and hands typed facts back, and the host
validates and commits them to Eshu core. This collector stores
nothing itself. All diagrams live in
[Diagrams](../diagrams/README.md); this page is the words.

## Where it sits

HashiCorp Vault -> this collector -> Eshu host process ->
Eshu core.

Overview diagram: [Where it sits](../diagrams/README.md#1-where-it-sits).

## One claim, start to finish

Collection is resilient per family. If one family can't be read,
the rest still emit, and the partial scope adds a
`secrets_iam_coverage_warning` fact so you know coverage was
incomplete.

Sequence diagram:
[One claim, start to finish](../diagrams/README.md#2-one-claim-start-to-finish).

## When something goes wrong

a claim for another collector kind or an unknown scope
isn't served against the wrong target. Each metadata family reads
independently; a family that fails doesn't sink the rest, and the
partial result carries a coverage warning. Retryable failures
with no upstream `Retry-After` use a 60-second default backoff.

Failure-flow diagram:
[When something goes wrong](../diagrams/README.md#3-when-something-goes-wrong).

## Trust boundary

- It never writes to the Eshu graph, Postgres, or any queue.
  It holds no Postgres, graph, queue, lease, or workflow handle,
  and it never imports the Eshu core module.
- It never reads a KV secret value; `/data/` reads are refused.
- It never emits a raw Vault name or path; fingerprints replace them.
- It never accepts a token from config or logs one.
- It never changes Vault; every API call is a read or list.
