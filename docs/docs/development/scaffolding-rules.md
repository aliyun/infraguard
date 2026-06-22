---
title: Scaffolding & Testing Rules
---

# Scaffolding & Testing Custom Rules

InfraGuard ships 600+ built-in rules, but most teams also have private compliance
requirements (naming conventions, mandatory cost tags, internal CIDR rules…).
This page shows the fast path to author and verify your own rules without leaving
the CLI.

The loop is: **`policy new` → edit → `policy test` → `scan`**.

## 1. Scaffold a rule

```bash
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance \
  --name-en "ECS instance must have owner tag" \
  --name-zh "ECS 实例必须包含 owner 标签"
```

This generates a ready-to-edit skeleton under `./policies` (override with `--dir`):

```
policies/
├── rules/
│   ├── ros/ecs-instance-must-have-owner-tag.rego
│   └── terraform/ecs-instance-must-have-owner-tag.rego
└── testdata/aliyun/rules/ecs-instance-must-have-owner-tag/
    ├── ros/{compliant.yaml, violation.yaml}
    └── terraform/{compliant/main.tf, violation/main.tf}
```

The generated `.rego` pre-fills the `rule_meta` block (id, severity, 7-language
name placeholders, resource types) and a minimal `deny` rule with `TODO` markers.
Custom rules can freely import the built-in helpers (`data.infraguard.helpers`,
`data.infraguard.helpers.terraform`) — InfraGuard injects them automatically when
you scan or test. See [Helper Functions](./helper-functions) and
[Writing Rules](./writing-rules).

## 2. Implement the logic

Edit the generated files and replace the `TODO` markers. For example, the ROS rule:

```rego
is_compliant(resource) if {
	helpers.has_tags(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Tags"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
```

Then make the fixtures meaningful: the `compliant` fixture should satisfy the rule
(e.g. include the `owner` tag) and the `violation` fixture should break it.

## Testing Rules

`infraguard policy test` evaluates each rule against its fixtures using the same
engine as `scan`:

- `compliant` fixtures must produce **no** violations of the rule.
- `violation` fixtures must produce **at least one**.

```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule ecs-instance-must-have-owner-tag
infraguard policy test --dir ./policies --iac terraform
infraguard policy test --dir ./policies --format json   # machine-readable, for CI
```

Example output:

```
RULE                              CASE                  STATUS
ecs-instance-must-have-owner-tag  ros/compliant         ✓ pass
ecs-instance-must-have-owner-tag  ros/violation         ✓ pass
ecs-instance-must-have-owner-tag  terraform/compliant   ✓ pass
ecs-instance-must-have-owner-tag  terraform/violation   ✓ pass

1 rules, 4 cases: 4 passed, 0 failed
```

Exit codes: `0` all pass, `1` a case failed, `2` no fixtures found (override with
`--allow-empty`). This makes `policy test` a natural CI gate for a custom-rule repo.

## 3. Use the rule in a scan

Point `scan` at your policy directory:

```bash
infraguard scan -p ./policies my-template.yaml
```

## Tips

- Use `infraguard policy validate ./policies` for static checks (syntax,
  `rule_meta` completeness) before `policy test` runs the behavior tests.
- Keep the ROS and Terraform implementations of the same rule under the same ID;
  they share the rule's metadata and are merged automatically.
- See the [policy CLI reference](../cli/policy) for the full flag list.
