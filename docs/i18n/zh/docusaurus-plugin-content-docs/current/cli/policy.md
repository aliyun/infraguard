---
title: infraguard policy
---

# infraguard policy

管理合规策略。

## 子命令

### list

列出所有可用策略：
```bash
infraguard policy list
```

### get

获取特定策略的详细信息：
```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### update

更新策略库：
```bash
infraguard policy update
```

### new

生成一条新的自定义规则脚手架（Rego 骨架 + 测试 fixture）：
```bash
# Generate a rule for both ROS and Terraform
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance

# Generate a compliance pack skeleton
infraguard policy new --pack my-team-baseline
```

生成的文件位于 `--dir` 之下（默认 `./policies`），可直接配合 `infraguard scan -p ./policies <template>` 和 `infraguard policy test` 使用。请参阅[编写自定义规则](../development/scaffolding-rules)。

| 选项 | 说明 | 默认值 |
| --- | --- | --- |
| `--iac` | 目标 IaC：`ros`、`terraform` 或 `both` | `both` |
| `--severity` | `high`、`medium` 或 `low` | `medium` |
| `--resource-type` | ROS 资源类型（可重复） | — |
| `--tf-resource-type` | Terraform 资源类型（可重复） | — |
| `--dir` | 输出根目录 | `./policies` |
| `--name-en` / `--name-zh` | 规则名称 | 规则 ID |
| `--desc-en` / `--desc-zh` | 规则描述 | `TODO` |
| `--no-test` | 不生成测试 fixture | `false` |
| `--force` | 覆盖已有文件 | `false` |
| `--pack` | 使用给定的 ID 生成包骨架 | — |

### test

使用规则的 fixture 运行其行为测试：
```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule my-rule --iac terraform
infraguard policy test --dir ./policies --format json
```

对于每条规则，`<dir>/testdata/aliyun/rules/<rule>/` 下的 fixture 会被评估：`compliant` fixture 必须**不**产生该规则的违规，`violation` fixture 必须产生**至少一个**违规。当所有用例通过时退出代码为 `0`，失败时为 `1`，未找到 fixture 时为 `2`（除非指定 `--allow-empty`）。请参阅[测试规则](../development/scaffolding-rules)。

| 选项 | 说明 | 默认值 |
| --- | --- | --- |
| `--dir` | 包含 `rules/` 和 `testdata/` 的根目录 | `./policies` |
| `--rule` | 仅测试给定的规则 ID（可重复） | 全部 |
| `--iac` | 要测试的 IaC：`ros`、`terraform` 或 `both` | `both` |
| `--format` | 输出格式：`table` 或 `json` | `table` |
| `--allow-empty` | 即使未找到 fixture 也以 `0` 退出 | `false` |

### validate

验证自定义策略：
```bash
infraguard policy validate my-rule.rego
infraguard policy validate ./policies/ --lang zh
```

### format

格式化策略文件：
```bash
infraguard policy format rule.rego
infraguard policy format rule.rego --write
infraguard policy format rule.rego --diff
```

### clean

清理用户策略目录：
```bash
infraguard policy clean              # 交互式模式，需要确认
infraguard policy clean --force      # 跳过确认
infraguard policy clean -f           # 短标志
```

删除 `~/.infraguard/policies/` 中的所有策略。不会影响内嵌策略或工作区策略。

有关更多详细信息，请参阅[管理策略](../user-guide/managing-policies)。

