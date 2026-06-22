---
title: 豁免
---

# 豁免（Suppressions）

当某个违规是已知且被接受的——例如遗留资源、风险已在别处缓解、临时例外——你可以**豁免**它，
而不必完全禁用规则或绕过 InfraGuard。豁免是一项明确且可审计的决策：它始终携带一个理由，并且最好带有过期日期。

InfraGuard 绝不会悄无声息地丢弃已豁免的发现项。处于活动状态的豁免会从默认输出中隐藏，但仍会计入汇总；
已过期的豁免会作为真实违规重新出现，以便及时续期。

## 两种豁免方式

### 1. 内联注释

直接在模板中对资源进行标注。同时适用于 ROS（YAML）和 Terraform（HCL）：

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

语法：

```
infraguard:ignore=<rule-id>[,<rule-id>...] reason="..." [expires=YYYY-MM-DD]
infraguard:ignore=*  reason="..."     # 抑制该资源上的所有规则
```

放置在资源上方或就近位置的指令将应用于该资源。不带 `reason` 的指令会被忽略。

### 2. 中心化豁免文件

对于批量或受治理的豁免，可以将一个 `.infraguard/waivers.yaml` 提交到你的仓库
（它和其他任何改动一样会经过代码评审）：

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

| 字段 | 含义 | 是否必需 |
| --- | --- | --- |
| `rule` | 短规则 ID，或 `*` 表示所有规则 | 是 |
| `resource` | 资源 ID，精确匹配或 glob | 否（任意资源） |
| `files` | 文件路径 glob（`*`、`**`） | 否（任意文件） |
| `reason` | 理由说明 | 是 |
| `expires` | `YYYY-MM-DD`；为空表示永久 | 否（推荐） |
| `owner` | 责任人 | 否（推荐） |

对于同一资源，内联指令优先于文件豁免。

## 扫描期间的行为

- **活动**豁免 → 该违规被隐藏，并在汇总中计为 `waived`。
- **过期**豁免 → 该违规被重新显示，并默认导致构建失败。
- **无豁免** → 作为普通违规处理。

```bash
infraguard scan -p pack:aliyun:... template.yaml          # waivers applied automatically
infraguard scan ... --show-waived template.yaml           # show what was waived
infraguard scan ... --no-waivers template.yaml            # full view, ignore all waivers
infraguard scan ... --fail-on-expired=false template.yaml # don't fail on expired waivers
```

对于 CI，安全团队可以运行 `--no-waivers` 以查看完整情况，或者保留豁免但依赖默认的
`--fail-on-expired` 来强制续期。

## 治理豁免

```bash
infraguard waiver list    # show every waiver and its status
infraguard waiver lint    # find missing reasons, unknown rules, expired entries
```

将 `waiver lint` 加入 pre-commit 或 CI，以保持豁免文件本身的健康。
请参阅 [waiver CLI 参考](../cli/waiver)。

## 关于安全性的说明

豁免确实会隐藏风险，因此它们被有意地施加了约束：`reason` 是强制的、已过期的豁免默认会导致失败、
JSON 输出始终保留已豁免项以便审计，并且豁免文件需经过 Git 评审。请优先使用范围更窄的豁免
（rule + resource + file），而非宽泛的豁免，并始终设置 `expires` 日期。
