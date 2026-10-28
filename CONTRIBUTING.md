# Contributing

## Local checks

`make ci` is the whole local contract: it runs the `lint`, `test`, and
`race` lane commands from `.github/workflows/ci.yml`, including the
coverage floor. Run it before every push. The one external binary is
`golangci-lint` at v2.12.2 (the version Eshu uses):

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
```

## CI lanes

Job names are stable across every collector repo. Only `ci-complete` is
required for merge; it passes when needed lanes pass and legitimately
skipped lanes stay skipped.

| PR changes | Lanes that run |
|---|---|
| Docs only (`README.md`, `LICENSE`, `CODEOWNERS`, `*.md`) | none |
| Go sources, `go.mod`, `go.sum`, `.golangci.yml`, `Makefile` | `lint`, `test`, `race`, `boundary` |
| Fixtures tests read (`manifest.yaml`: `go:embed` in `manifest.go`, read by `manifest_test.go`) | `test` only |
| Shell scripts (`**/*.sh`; no test executes one today) | `shell` only |
| `Dockerfile`, `.dockerignore`, `manifest.yaml` (embedded, so a manifest change rebuilds the image) | `test`, `image` |
| `go.mod` / `go.sum` / `.golangci.yml` | above plus `govulncheck` |
| `.github/workflows/**`, `.github/dependabot.yml` | `actionlint`, plus `lint`, `test`, `race`, `boundary`, `image` |
| Push to `main`, weekly schedule | every default-on lane; the schedule files or updates an issue on findings |

Lane bodies live in the shared `eshu-hq/.github` `go-collector-ci`
reusable workflow (pinned by SHA in `ci.yml`); job names are identical
there. `lint` runs `go vet`, whole-repo `golangci-lint` (no baselines),
the `gofumpt` format check, and `go mod tidy`. `boundary` runs the
`replace`-directive ban (the import boundary itself is enforced by
`boundary_test.go` on the `test` lane), and the 500-line file cap lives in
`lint`. `race` runs the whole module with `-race`, uploads the coverprofile
(14-day retention), and fails below `COVERAGE_FLOOR`.

## Rules that do not bend

- The coverage floor lives in `ci.yml` as `COVERAGE_FLOOR` and may only
  rise. The finish line is 90% of statements; never close a gap by lowering
  the target, excluding packages silently, or deleting assertions.
- No `.go` file may exceed 500 lines (plain `wc -l` step, no plugin).
- No static gates besides that cap: no committed counts, lists, or parity
  files. Lint, format, vet, build, tests, and race judge the code itself.
- Lint runs on the whole repo. Any exclusion in `.golangci.yml` needs a
  reason and a linked open issue.
- `gosec` is advisory (SARIF artifact, never blocking PRs) until its
  false-positive rate here is measured. Triage findings in the open with
  per-site `#nosec` reasons; never blanket-exclude a rule.
- All GitHub Actions are pinned by commit SHA in the `release.yml` style.
- Dependabot proposes weekly grouped updates for Go modules and actions.
  The `govulncheck` lane stays the backstop and fails the PR on reachable
  findings.
