---
title: infraguard policy
---

# infraguard policy

Manage compliance policies.

## Subcommands

### list

List all available policies:
```bash
infraguard policy list
```

Filter the listing by policy type:
```bash
infraguard policy list --type rule
infraguard policy list --type pack
infraguard policy list --type scenario-packs
```

`--type scenario-packs` shows the eight top-level Alibaba Cloud scenario packs:
`best-practice`, `compliance`, `cost-optimization`, `elasticity`, `high-availability`,
`network-architecture`, `operations`, and `security`. Each top-level scenario pack is
an explicit directory roll-up: its `pack_meta.rules` keeps the top-level pack's curated
rules and adds the de-duplicated rules referenced by the other packs in the same
`policies/aliyun/packs/<scenario>/` directory. The smaller packs remain available for
targeted scans.

### get

Get details of a specific policy:
```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### update

Update the policy library:
```bash
infraguard policy update
```

### new

Scaffold a new custom rule (Rego skeleton + test fixtures):
```bash
# Generate a rule for both ROS and Terraform
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance

# Generate a compliance pack skeleton
infraguard policy new --pack my-team-baseline
```

Generated files live under `--dir` (default `./policies`) and can be used directly with `infraguard scan -p ./policies <template>` and `infraguard policy test`. See [Authoring Custom Rules](../development/scaffolding-rules).

| Flag | Description | Default |
| --- | --- | --- |
| `--iac` | Target IaC: `ros`, `terraform`, or `both` | `both` |
| `--severity` | `high`, `medium`, or `low` | `medium` |
| `--resource-type` | ROS resource type (repeatable) | — |
| `--tf-resource-type` | Terraform resource type (repeatable) | — |
| `--dir` | Output root directory | `./policies` |
| `--name-en` / `--name-zh` | Rule name | rule ID |
| `--desc-en` / `--desc-zh` | Rule description | `TODO` |
| `--no-test` | Do not generate test fixtures | `false` |
| `--force` | Overwrite existing files | `false` |
| `--pack` | Generate a pack skeleton with the given ID | — |

### test

Run behavior tests for rules using their fixtures:
```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule my-rule --iac terraform
infraguard policy test --dir ./policies --format json
```

For each rule, fixtures under `<dir>/testdata/aliyun/rules/<rule>/` are evaluated: `compliant` fixtures must produce **no** violations of the rule, and `violation` fixtures must produce **at least one**. Exit code is `0` when all cases pass, `1` on failure, and `2` when no fixtures are found (unless `--allow-empty`). See [Testing Rules](../development/scaffolding-rules).

| Flag | Description | Default |
| --- | --- | --- |
| `--dir` | Root directory containing `rules/` and `testdata/` | `./policies` |
| `--rule` | Only test the given rule ID (repeatable) | all |
| `--iac` | IaC to test: `ros`, `terraform`, or `both` | `both` |
| `--format` | Output format: `table` or `json` | `table` |
| `--allow-empty` | Exit `0` even when no fixtures are found | `false` |

### validate

Validate custom policies:
```bash
infraguard policy validate my-rule.rego
infraguard policy validate ./policies/ --lang zh
```

### format

Format policy files:
```bash
infraguard policy format rule.rego
infraguard policy format rule.rego --write
infraguard policy format rule.rego --diff
```

### clean

Clean user policy directory:
```bash
infraguard policy clean              # Interactive mode with confirmation
infraguard policy clean --force      # Skip confirmation
infraguard policy clean -f           # Short flag
```

Removes all policies from `~/.infraguard/policies/`. Does not affect embedded policies or workspace policies.

For more details, see [Managing Policies](../user-guide/managing-policies).
