# Configuration

There's no `config.example.*` file in this repo. The host request
`config` object is the configuration, decoded by `ParseSettings`
in `config.go`. Parse errors name config keys only and never quote
a configured value, so a bad config won't leak anything into an
error message.

| Name | Required | Default | What it does |
|---|---|---|---|
| `collector_instance_id` | Yes | None | Instance that owns target policy |
| `targets` | Yes, at least one | None | Vault targets this instance may collect |
| `targets[].vault_cluster_id` | Yes | None | Durable identity of one Vault cluster |
| `targets[].address` | Yes | None | Vault HTTPS address for the target |
| `targets[].token_env` | Yes | None | Name of the env var holding the read-only token |
| `targets[].namespace` | No | Empty | Vault namespace for the target |
| `targets[].display_name` | No | Empty | Operator-facing target label |
| `targets[].environment` | No | Empty | Operator-declared environment label |
| `targets[].source_uri` | No | Sanitized target address | Credential-free source address recorded on facts |
| `ESHU_VAULT_LIVE_REDACTION_KEY` (env) | Yes | None | Key material for name and path fingerprints |

A few rules that surprise people. Two targets with the same
cluster and namespace are rejected. Any target key containing
`token` other than `token_env`, or naming `secret`, `password`,
`credential`, `api_key`, or `private_key`, fails closed; config is
for names of things, never the things themselves. The token named
by `token_env` must be present and non-empty in the process
environment at claim time.

## Credentials and least privilege

The read-only Vault token resolves from the environment variable
that `token_env` names; it never appears in claim config, facts,
logs, or metric labels. The redaction key resolves from
`ESHU_VAULT_LIVE_REDACTION_KEY` the same way.

In code, the client reads only these Vault API families:
`sys/auth`, `sys/mounts`, `sys/policies/acl` (list and read),
`auth/<mount>/role` listings, `identity/entity/id`,
`identity/entity-alias/id`, and KV metadata paths. Grant the token
only the read and list access those metadata paths need, and stop
there. This repo ships no Vault policy file, so don't copy a
policy from another repo without checking it against that list.
KV `/data/` reads are refused in the client, so the token needs no
access to secret values at all.

## Claim budget

The transport caps one request at 1 MiB (`1 << 20` bytes) and one
result at 32 MiB (`32 << 20` bytes). The claim deadline comes from
the host request; an expired deadline is a transport failure, not
a served claim.

---

Looking for what comes out the other side? See [Facts](facts.md).
Stuck on a value? [Troubleshoot](../guides/troubleshoot.md) covers
the failures people hit most.
