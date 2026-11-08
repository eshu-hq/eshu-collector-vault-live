# Troubleshoot

Start with the symptom you have. Most of these end at a config
value, so keep [Configuration](../reference/configuration.md) open
in another tab.

- `config_failure` events? Check for the usual suspects: a
  duplicate cluster-plus-namespace target, a forbidden key such as
  a literal `token`, or an empty env var behind `token_env`.
- `unknown_scope` events? The claim doesn't match any configured
  target. Claims for any other collector kind or source system
  are rejected too.
- Coverage warnings in the facts? One metadata family couldn't be
  read. The rest still emitted; check that the token can list and
  read the family named by the warning.
- Non-zero exit with no claim served? That's transport, not
  collection: oversize request, expired deadline, malformed JSON,
  foreign claim kind, or a usage error.

## Still stuck?

Re-read the failure flow in
[Diagrams](../diagrams/README.md#3-when-something-goes-wrong) and
check which branch your run took. If the result looks complete but
wrong, compare it against [Facts](../reference/facts.md) before
suspecting the source.
