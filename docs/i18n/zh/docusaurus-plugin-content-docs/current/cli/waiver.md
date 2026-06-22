---
title: infraguard waiver
---

# infraguard waiver

管理规则豁免（抑制）。豁免允许你在知情的前提下，使用一个理由和可选的过期日期来抑制特定违规。
有关概念和豁免文件格式，请参阅[豁免指南](../user-guide/waivers)。

## 子命令

### list

列出所有豁免及其状态（active / expired / permanent）：
```bash
infraguard waiver list
infraguard waiver list --waivers ./path/to/waivers.yaml
```

### lint

校验豁免文件——标记缺失的理由、未知规则、无效或已过期的日期：
```bash
infraguard waiver lint
infraguard waiver lint --rules-dir ./policies/rules   # 同时识别自定义规则
```

当存在错误时（例如缺少 `reason`），`lint` 会以非零状态码退出，因此适合用作针对豁免文件本身的
pre-commit 钩子或 CI 门禁。

## 选项

| 选项 | 说明 | 默认值 |
| --- | --- | --- |
| `--waivers` | 豁免文件路径 | 自动检测 `.infraguard/waivers.yaml` |
| `--rules-dir` | （`lint`）同时将此目录下的规则视为已知规则 | — |

## 相关的 scan 选项

豁免在 `infraguard scan` 期间生效。相关选项如下：

| 选项 | 说明 | 默认值 |
| --- | --- | --- |
| `--waivers` | 豁免文件路径 | 自动检测 |
| `--no-waivers` | 忽略所有豁免（内联注释和文件） | `false` |
| `--show-waived` | 显示已豁免的违规，而非隐藏它们 | `false` |
| `--fail-on-expired` | 将已过期的豁免视为真实违规 | `true` |

请参阅 [infraguard scan](./scan) 和[豁免指南](../user-guide/waivers)。
