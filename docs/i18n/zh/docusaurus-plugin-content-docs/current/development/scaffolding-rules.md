---
title: 脚手架与测试规则
---

# 脚手架与测试自定义规则

InfraGuard 内置 600+ 条规则，但大多数团队还有自己的私有合规需求（命名规范、强制成本标签、内部 CIDR 规则……）。
本页介绍在不离开 CLI 的情况下，编写并验证自己规则的快捷路径。

整个流程是：**`policy new` → 编辑 → `policy test` → `scan`**。

## 1. 生成规则脚手架

```bash
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance \
  --name-en "ECS instance must have owner tag" \
  --name-zh "ECS 实例必须包含 owner 标签"
```

这会在 `./policies` 下生成一个可直接编辑的骨架（可通过 `--dir` 覆盖）：

```
policies/
├── rules/
│   ├── ros/ecs-instance-must-have-owner-tag.rego
│   └── terraform/ecs-instance-must-have-owner-tag.rego
└── testdata/aliyun/rules/ecs-instance-must-have-owner-tag/
    ├── ros/{compliant.yaml, violation.yaml}
    └── terraform/{compliant/main.tf, violation/main.tf}
```

生成的 `.rego` 会预先填充 `rule_meta` 块（id、severity、7 种语言的名称占位符、资源类型）以及一个带有
`TODO` 标记的最小 `deny` 规则。自定义规则可以自由导入内置辅助函数（`data.infraguard.helpers`、
`data.infraguard.helpers.terraform`）——当你执行扫描或测试时，InfraGuard 会自动注入它们。
请参阅[辅助函数](./helper-functions)和[编写规则](./writing-rules)。

## 2. 实现逻辑

编辑生成的文件并替换 `TODO` 标记。例如 ROS 规则：

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

然后让 fixture 变得有意义：`compliant` fixture 应当满足规则（例如包含 `owner` 标签），
而 `violation` fixture 应当违反规则。

## 测试规则

`infraguard policy test` 使用与 `scan` 相同的引擎，针对每条规则的 fixture 进行评估：

- `compliant` fixture 必须**不**产生该规则的违规。
- `violation` fixture 必须产生**至少一个**违规。

```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule ecs-instance-must-have-owner-tag
infraguard policy test --dir ./policies --iac terraform
infraguard policy test --dir ./policies --format json   # machine-readable, for CI
```

示例输出：

```
RULE                              CASE                  STATUS
ecs-instance-must-have-owner-tag  ros/compliant         ✓ pass
ecs-instance-must-have-owner-tag  ros/violation         ✓ pass
ecs-instance-must-have-owner-tag  terraform/compliant   ✓ pass
ecs-instance-must-have-owner-tag  terraform/violation   ✓ pass

1 rules, 4 cases: 4 passed, 0 failed
```

退出代码：`0` 全部通过，`1` 某个用例失败，`2` 未找到 fixture（可通过 `--allow-empty` 覆盖）。
这使得 `policy test` 成为自定义规则仓库中天然的 CI 门禁。

## 3. 在扫描中使用规则

让 `scan` 指向你的策略目录：

```bash
infraguard scan -p ./policies my-template.yaml
```

## 提示

- 在 `policy test` 运行行为测试之前，使用 `infraguard policy validate ./policies` 进行静态检查
  （语法、`rule_meta` 完整性）。
- 将同一规则的 ROS 和 Terraform 实现保持在相同的 ID 下；它们共享规则的元数据并会被自动合并。
- 完整的选项列表请参阅 [policy CLI 参考](../cli/policy)。
