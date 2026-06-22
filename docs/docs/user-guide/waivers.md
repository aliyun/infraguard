---
title: Waivers
---

# Waivers (Suppressions)

When a violation is known and accepted — a legacy resource, a risk mitigated
elsewhere, a temporary exception — you can **waive** it instead of disabling the
rule entirely or bypassing InfraGuard. A waiver is an explicit, auditable decision:
it always carries a reason and, ideally, an expiry date.

InfraGuard never silently drops a waived finding. Active waivers are hidden from
the default output but counted in the summary; expired waivers resurface as real
violations so they get renewed.

## Two ways to waive

### 1. Inline comments

Annotate the resource directly in the template. Works for both ROS (YAML) and
Terraform (HCL):

```yaml
Resources:
  # infraguard:ignore=oss-bucket-public-read-prohibited reason="legacy bucket, migrating 2026Q4" expires=2026-12-31
  LegacyBucket:
    Type: ALIYUN::OSS::Bucket
    Properties:
      AccessControl: public-read
```

```hcl
resource "alicloud_oss_bucket" "legacy" {
  # infraguard:ignore=oss-bucket-public-read-prohibited reason="legacy bucket" expires=2026-12-31
  bucket = "legacy"
  acl    = "public-read"
}
```

Syntax:

```
infraguard:ignore=<rule-id>[,<rule-id>...] reason="..." [expires=YYYY-MM-DD]
infraguard:ignore=*  reason="..."     # suppress all rules on this resource
```

A directive placed on or just above a resource applies to that resource. A
directive without a `reason` is ignored.

### 2. Central waiver file

For batch or governed waivers, commit a `.infraguard/waivers.yaml` to your repo
(it goes through code review like any other change):

```yaml
version: 1
waivers:
  - rule: oss-bucket-public-read-prohibited
    resource: "LegacyBucket"          # exact ID or glob, e.g. "legacy-*"
    files: ["envs/legacy/**"]          # optional file globs (supports **)
    reason: "Legacy resource, approved in CAB-1234"
    expires: 2026-09-30
    owner: alice@example.com

  - rule: rds-instance-enabled-tde
    resource: "*"                      # all matching resources
    files: ["sandbox/**"]
    reason: "Sandbox environment does not require TDE"
    # no expires → permanent waiver (flagged by `waiver lint`)
```

| Field | Meaning | Required |
| --- | --- | --- |
| `rule` | Short rule ID, or `*` for all rules | Yes |
| `resource` | Resource ID, exact or glob | No (any resource) |
| `files` | File path globs (`*`, `**`) | No (any file) |
| `reason` | Justification | Yes |
| `expires` | `YYYY-MM-DD`; empty means permanent | No (recommended) |
| `owner` | Responsible person | No (recommended) |

Inline directives take precedence over file waivers for the same resource.

## Behavior during a scan

- **Active** waiver → the violation is hidden and counted as `waived` in the summary.
- **Expired** waiver → the violation is shown again and, by default, fails the build.
- **No waiver** → a normal violation.

```bash
infraguard scan -p pack:aliyun:... template.yaml          # waivers applied automatically
infraguard scan ... --show-waived template.yaml           # show what was waived
infraguard scan ... --no-waivers template.yaml            # full view, ignore all waivers
infraguard scan ... --fail-on-expired=false template.yaml # don't fail on expired waivers
```

For CI, a security team can run `--no-waivers` to see the full picture, or keep
waivers but rely on the default `--fail-on-expired` to force renewals.

## Governing waivers

```bash
infraguard waiver list    # show every waiver and its status
infraguard waiver lint    # find missing reasons, unknown rules, expired entries
```

Add `waiver lint` to pre-commit or CI so the waiver file itself stays healthy.
See the [waiver CLI reference](../cli/waiver).

## A note on safety

Waivers legitimately hide risk, so they are constrained on purpose: a `reason` is
mandatory, expired waivers fail by default, JSON output always retains waived
items for auditing, and the file is reviewed through Git. Prefer narrow waivers
(rule + resource + file) over broad ones, and always set an `expires` date.
