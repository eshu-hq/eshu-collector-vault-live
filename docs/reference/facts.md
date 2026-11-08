# Facts

You'll learn which auth methods, policies, identities, and secret
engines a Vault cluster has, without ever reading a secret value.

The table below mirrors `spec.emittedFacts` in
[manifest.yaml](../../manifest.yaml); update this table in the same
change as the manifest. That file declares 8 fact kinds, all at
schema version `1.0.0` with `reported` confidence (Vault reported
it).

| Fact kind | What you get |
|---|---|
| `vault_auth_mount` | One enabled login method (auth mount) |
| `vault_auth_role` | One role under a login method |
| `vault_acl_policy` | One ACL policy: rules for who may do what |
| `vault_identity_entity` | One Vault identity (a who known to Vault) |
| `vault_identity_alias` | One link from a login identity to a Vault identity |
| `vault_kv_metadata` | Metadata about one key-value secret path, never its value |
| `vault_secret_engine_mount` | One enabled secrets engine |
| `secrets_iam_coverage_warning` | Part of the target could not be read fully |

New to the words *fact* and *claim*? [Concepts](../concepts/README.md) defines them in plain language.
