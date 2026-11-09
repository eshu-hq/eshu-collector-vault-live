# Diagrams

Every diagram for this collector lives on this page, each with a
caption and a plain-text version so nothing depends on rendering.
Other pages link here instead of copying a diagram. (The repo
[README](../../README.md) keeps the first one as its overview.)

## 1. Where it sits

*Caption: source data flows into this collector, then to the Eshu
host process, then to Eshu core. The collector itself stores
nothing.*

```mermaid
flowchart LR
    V[HashiCorp Vault HTTPS API] --> C[This collector]
    C --> H[Eshu host process]
    H --> E[Eshu core]
```

Text version: HashiCorp Vault -> this collector -> Eshu host process ->
Eshu core.

## 2. One claim, start to finish

*Caption: one process invocation serves exactly one claim. The host
writes the request, the collector reads the claimed scope, facts
come back on stdout, and the host validates and commits.*

```mermaid
sequenceDiagram
    participant H as Eshu host process
    participant C as This collector
    participant V as HashiCorp Vault (HTTPS API)
    participant E as Eshu core
    H->>C: one claim on stdin (--sdk-stdio)
    C->>V: read setup metadata for the claimed target
    V-->>C: mounts, roles, policies, identities, KV metadata
    C-->>H: one result with facts on stdout
    H->>E: validate and commit the facts
```

Text version: the host writes one `collector-sdk/v1alpha1` request to
stdin, the collector reads the claimed target's setup metadata and
builds facts, then writes one result to stdout. The host builds
the core fact envelope, validates the result, and commits. Claims
for any other collector kind or source system are rejected.

## 3. When something goes wrong

*Caption: the failure paths. Bounded, fail-closed outcomes are
preferred over late, oversized, or silently incomplete evidence;
partial reads say so instead of pretending.*

```mermaid
flowchart TD
    S[Claim arrives] --> K{Claim kind and scope match a target?}
    K -- no --> U[Diagnostic event unknown_scope; claim not served for another target]
    K -- yes --> F[Read each metadata family]
    F --> P{Every family read?}
    P -- no --> W[Emit what read plus a secrets_iam_coverage_warning fact]
    P -- yes --> O[Return facts on stdout, exit 0]
    W --> O
```

Text version: a claim for another collector kind or an unknown scope
isn't served against the wrong target. Each metadata family reads
independently; a family that fails doesn't sink the rest, and the
partial result carries a coverage warning. Retryable failures
with no upstream `Retry-After` use a 60-second default backoff.
