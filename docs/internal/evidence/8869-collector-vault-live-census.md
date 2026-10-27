# #8869 collector-vault-live extraction census (extracted-repo port)

## Scope

Repository `eshu-hq/eshu-collector-vault-live`, branch
`scaffold/8869-initial` off `main`.

This record ports the #8869 acceptance-criterion-2 extraction census from
the core repository
(`docs/internal/evidence/8869-collector-vault-live-census.md` in `eshu-hq/eshu`,
landed via `eshu-hq/eshu#9265`) into the extracted collector repository. It
answers AC2 (packages, fact kinds, consumers, durable-state ownership,
protocols, artifacts, migration stage, prerequisites) and the
credential-handling half of criterion 7 for the `collector-vault-live` to
`eshu-collector-vault-live` cutover. It moves no collector logic and
authorizes no release, deployment, rollback, or in-tree removal.

Migration stage: `planned`. Destination and owner are assigned by
`docs/internal/design/eshu-ecosystem-repository-migration.md` in the core
repository (row: `collector-vault-live` to `eshu-collector-vault-live`);
prerequisites remain. This repository holds no producer authority until the
reviewed cutover rehearsal lands the producer grant here.

## Source command (in-tree origin)

`go/cmd/collector-vault-live/` in `eshu-hq/eshu` (`main.go`, `service.go`,
`config.go`, `doc.go`, `config_test.go`, plus `AGENTS.md`/`README.md`).
Binary `eshu-collector-vault-live`. Two launch modes: `claimed-live`
(default) and `cassette` (`-cassette-file`, credential-free, 24h poll).

`main.go` hosts via the shared app host with `/healthz`, `/readyz`,
`/metrics`, and `/admin/status`. `service.go:buildClaimedService` wires
`vaultlive.NewClaimedSource` onto the shared collector commit boundary
(`postgres.NewIngestionStore`) with `postgres.NewWorkflowControlStore` claims;
`buildCassetteService` wires `cassette.NewSource` with no Vault credentials.
The scope identity is `vault_live` on both sides of the boundary:
`scope.CollectorVaultLive` (see `go/internal/scope/collector_kind.go`, symbol
`CollectorVaultLive` in `eshu-hq/eshu`) equals `vaultlive.CollectorKind` (see
`go/internal/collector/vaultlive/snapshot.go`, symbol `CollectorKind`);
`runtime/extraction_census_test.go` in this repository locks the extracted
half of that agreement to the `vault_live` literal.

## Extracted packages (this repository)

- `runtime/` (`boundary.go`, plus `doc.go`): scope identity
  (`CollectorKind = "vault_live"`), cross-boundary target and config types
  (`ClusterTarget`, `Config`), the deployment-scoped redaction-key handle
  (`Key`), and the `(cluster, namespace)` factory key (`authKey`). Ported
  from `go/internal/collector/vaultlive/snapshot.go`
  (`CollectorKind`, `ClusterTarget`, `Config`), `go/internal/redact`
  (`Key`), and `go/cmd/collector-vault-live/service.go` (`authKey`) in
  `eshu-hq/eshu`.
- `document/` (`kinds.go`, plus `doc.go`): emitted fact-kind vocabulary.
  Ported from the `go/internal/collector/vaultlive/map.go` mappers
  (`mapAuthMount`, `mapAuthRole`, `mapACLPolicy`, `mapIdentityEntity`,
  `mapIdentityAlias`, `mapKVMetadata`, `mapSecretEngineMount`) in
  `eshu-hq/eshu`.
- Shared commit boundary (stays in core per the migration plan):
  `go/internal/collector` (`Service`, `ClaimedService`),
  `go/internal/replay/cassette`, `go/internal/scope`
  (`scope.CollectorVaultLive`), workflow claim/lease
  (`DefaultClaimMaxAttempts`, `DefaultClaimLeaseTTL`,
  `DefaultHeartbeatInterval`), `go/internal/storage/postgres`
  (`NewIngestionStore`, `NewWorkflowControlStore`,
  `NewInstrumentedStatusStore`), `go/internal/telemetry`,
  `go/internal/app`, `go/internal/runtime`.

## Fact kinds

Seven source facts plus one coverage warning, all metadata-only:

- `vault_auth_mount`
- `vault_auth_role`
- `vault_acl_policy`
- `vault_identity_entity`
- `vault_identity_alias`
- `vault_kv_metadata`
- `vault_secret_engine_mount`
- `secrets_iam_coverage_warning` on partial scope.

Names and paths are HMAC-fingerprinted before emission; metric labels are
bounded enums only (`source="vault"`, operation, result).

## Consumers

- Reducer secrets-IAM graph projection (`go/internal/reducer/*secretsiam*`
  in `eshu-hq/eshu`, including the additive-domains drift defaults).
- In-tree scheduler `go/internal/coordinator/vault/live/planner.go` (with
  `in_tree_schedulers.go`) in `eshu-hq/eshu`.
- Status and promotion catalog (`promotion_catalog.go`) and the
  capability/capability-inventory surfaces.

## Durable-state ownership

Core Postgres owns all durable state. The collector owns no tables:

- fact commits: `postgres.NewIngestionStore`;
- claims and leases: `postgres.NewWorkflowControlStore`;
- health and status: `postgres.NewInstrumentedStatusStore`.

Per the migration plan, facts, generations, admission, recovery, canonical
graph, workflow plans, claims, and scheduler state stay core-owned after
extraction; the extracted runtime must use the versioned fact-submission and
claim contracts, never shared-table shortcuts.

## Protocols

- Vault HTTPS API with a read-only token; list/get on metadata endpoints only.
- Postgres wire (core-owned stores above).
- OTLP traces and metrics (`SecretsIAMSourceFactsEmitted`, `PartialScope`,
  `ScopeFreshness`, `eshu_dp_vault_request_total`), Prometheus handler, pprof
  server, hosted status server.
- Configuration: `ESHU_COLLECTOR_INSTANCES_JSON` selects the one enabled
  claim-capable `vault_live` instance; per-target JSON carries
  `vault_cluster_id`, `namespace`, `address`, `token_env`, `source_uri`, and
  `fencing_token`. Runtime tuning via `ESHU_VAULT_LIVE_POLL_INTERVAL`,
  `ESHU_VAULT_LIVE_CLAIM_LEASE_TTL`, `ESHU_VAULT_LIVE_HEARTBEAT_INTERVAL`,
  `ESHU_VAULT_LIVE_COLLECTOR_INSTANCE_ID`,
  `ESHU_VAULT_LIVE_COLLECTOR_OWNER_ID`, and `ESHU_VAULT_LIVE_REDACTION_KEY`.

## Credential handling and redaction

- The token is never serialized in the targets JSON: `token_env` names the
  environment variable holding the read-only token
  (`config.go:30-42,162-186` in `eshu-hq/eshu`). An empty resolved token
  fails closed.
- The cross-boundary `runtime.ClusterTarget` carries non-secret identity
  only; connection details and the token live in the command-local
  `vaultClientFactory`, keyed by `authKey(cluster, namespace)` because the
  scope identity is namespace-scoped.
- `runtime.Config` carries the same identity plus exactly one documented
  exception: the deployment-scoped HMAC redaction key (`RedactionKey`,
  required for fingerprinting names and paths). It is secret material by this
  repository's own `runtime.Key` definition, never the Vault token, and
  `runtime/extraction_census_test.go` locks the exception to that single
  field.
- `ESHU_VAULT_LIVE_REDACTION_KEY` is required; names and paths are
  HMAC-fingerprinted with it. Heartbeat must stay below the claim-lease TTL.
- Do not log the token or the raw Vault address.
- `runtime/extraction_census_test.go` guards the boundary: no
  `token`/`secret`/`password`/`credential` field may appear on the
  cross-boundary structs (`FencingToken` is allowlisted only as a locked
  int64 generation counter), exactly one `Key` field is permitted and it must
  be the documented `Config.RedactionKey`, and `authKey` must separate both
  dimensions. `runtime/boundary_test.go` proves the fail-closed construction
  contract: blank identity, missing targets, a zero key, a blank cluster id,
  and a duplicate target scope are all rejected.

## Artifacts

- In-tree binary via the `main` package in `eshu-hq/eshu`; no standalone
  release artifact from this repository yet.
- Helm (in-tree): `deploy/helm/eshu/templates/deployment-vault-live-collector.yaml`
  (command `/usr/local/bin/eshu-collector-vault-live`, values-gated) and
  `service-vault-live-collector-metrics.yaml`.

## Prerequisites (closed, reused)

- #6708 SDK collector and fact-schema modules published.
- #6709 producer-grant authorization merged.
- #6710 standalone collector template and compatibility harness merged.
- #4047 extraction-readiness gate closed (8th criterion
  `payload_schemas_typed` enforced).

## TDD and focused proof

`runtime/extraction_census_test.go` was ported from
`go/cmd/collector-vault-live/extraction_census_test.go`
(`eshu-hq/eshu#9265`) against the same boundary rules and passes on the
extracted types. Focused proof:

```text
go test -count=1 ./...
go vet ./...
gofmt -l .
```

## Unresolved (NOT_CHECKED, owned by later cutover steps)

- Named implementation, public-contract, release, and deployment owners; the
  production target and configuration source beyond the owner-confirmed QA
  designation in #8869.
- Oldest/newest supported core and component version pairs; vulnerability
  response record.
- Producer-grant cutover rehearsal landing authority in this repository.
- Parity, projection, concurrency, resource, credential, rollback-rehearsal,
  and production-acceptance proofs on the extracted path.

No-Regression Evidence: this port moves no collector logic, alters no runtime
behavior, and claims no collector has cut over. The accompanying tests add
assertions only; they change no production path.

No-Observability-Change: this port adds no metric, span, log, status field,
or dashboard label.
