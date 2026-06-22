---
title: infraguard waiver
---

# infraguard waiver

Manage rule waivers (suppressions). Waivers let you knowingly suppress specific
violations with a reason and an optional expiry date. See the [Waivers guide](../user-guide/waivers)
for concepts and the waiver-file format.

## Subcommands

### list

List all waivers and their status (active / expired / permanent):
```bash
infraguard waiver list
infraguard waiver list --waivers ./path/to/waivers.yaml
```

### lint

Validate the waiver file — flags missing reasons, unknown rules, invalid or
expired dates:
```bash
infraguard waiver lint
infraguard waiver lint --rules-dir ./policies/rules   # also recognize custom rules
```

`lint` exits non-zero when there are errors (e.g. a missing `reason`), making it
suitable for a pre-commit hook or CI gate on the waiver file itself.

## Flags

| Flag | Description | Default |
| --- | --- | --- |
| `--waivers` | Path to the waiver file | auto-detect `.infraguard/waivers.yaml` |
| `--rules-dir` | (`lint`) Also treat rules under this directory as known | — |

## Related scan flags

Waivers are applied during `infraguard scan`. The relevant flags are:

| Flag | Description | Default |
| --- | --- | --- |
| `--waivers` | Path to the waiver file | auto-detect |
| `--no-waivers` | Ignore all waivers (inline comments and file) | `false` |
| `--show-waived` | Show waived violations instead of hiding them | `false` |
| `--fail-on-expired` | Treat expired waivers as real violations | `true` |

See [infraguard scan](./scan) and the [Waivers guide](../user-guide/waivers).
