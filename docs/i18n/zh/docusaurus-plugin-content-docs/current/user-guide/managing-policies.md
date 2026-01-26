---
title: 管理策略
---

# 管理策略

了解如何在 InfraGuard 中发现、管理和更新策略。

## 列出策略

### 列出所有策略

查看所有可用的规则和包：

```bash
infraguard policy list
```

这将显示：
- 所有内置规则
- 所有合规包
- 自定义策略（如果有）

### 按云服务商筛选

目前，InfraGuard 支持阿里云策略。未来版本将支持其他云服务商。

## 策略详情

### 获取规则信息

查看特定规则的详细信息：

```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
```

输出包括：
- 规则 ID 和名称
- 严重性级别
- 描述
- 失败原因
- 建议
- 受影响的资源类型

### 获取包信息

查看合规包详情：

```bash
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

输出包括：
- 包 ID 和名称
- 描述
- 包含的规则列表

## 更新策略

InfraGuard 包含嵌入式策略，但您也可以下载最新的策略库：

```bash
infraguard policy update
```

这将下载策略到 `~/.infraguard/policies/`，优先于嵌入式策略。

## 清理策略

要从用户目录中删除已下载的策略：

```bash
infraguard policy clean
```

此命令：
- 删除 `~/.infraguard/policies/` 中的所有策略
- 默认情况下提示确认
- 不影响嵌入式策略（它们仍然可用）
- 不影响 `.infraguard/policies/` 中的工作区策略

### 强制清理（无需确认）

对于脚本或非交互式环境：

```bash
infraguard policy clean --force
# 或
infraguard policy clean -f
```

### 策略加载优先级

InfraGuard 按以下优先级（从高到低）从三个来源加载策略：

1. **工作区本地策略**：`.infraguard/policies/`（相对于当前工作目录）
2. **用户本地策略**：`~/.infraguard/policies/`
3. **嵌入式策略**：内置到二进制文件中（后备）

同一 ID 的策略，高优先级来源会覆盖低优先级来源。这样可以实现：
- **项目专属策略**：在 `.infraguard/policies/` 中定义与项目一起版本控制的自定义规则
- **用户自定义**：通过 `~/.infraguard/policies/` 全局覆盖嵌入式策略
- **无缝后备**：内置策略开箱即用

## 验证自定义策略

在使用自定义策略之前，请验证它们：

```bash
infraguard policy validate ./my-custom-rule.rego
```

这将检查：
- Rego 语法
- 必需的元数据（`rule_meta` 或 `pack_meta`）
- 正确的 deny 规则结构

### 验证选项

```bash
# 验证单个文件
infraguard policy validate rule.rego

# 验证目录
infraguard policy validate ./policies/

# 指定输出语言
infraguard policy validate rule.rego --lang zh
```

## 格式化策略

使用 OPA 格式化程序格式化您的策略文件：

```bash
# 显示格式化输出
infraguard policy format rule.rego

# 将更改写回文件
infraguard policy format rule.rego --write

# 显示更改差异
infraguard policy format rule.rego --diff
```

## 策略组织

### 内置策略

位于二进制文件中的：
- `policies/aliyun/rules/` - 单个规则
- `policies/aliyun/packs/` - 合规包
- `policies/aliyun/lib/` - 辅助库

### 自定义策略

#### 工作区本地策略（项目专属）

将项目专属策略存储在项目目录中：
- `.infraguard/policies/<provider>/rules/` - 项目专属规则
- `.infraguard/policies/<provider>/packs/` - 项目专属包
- `.infraguard/policies/<provider>/lib/` - 项目专属辅助库

这些策略在项目目录内运行 InfraGuard 命令时会自动加载，可以与 IaC 模板一起进行版本控制。

#### 用户本地策略（全局）

将全局自定义策略存储在用户主目录中：
- `~/.infraguard/policies/<provider>/rules/` - 自定义规则
- `~/.infraguard/policies/<provider>/packs/` - 自定义包
- `~/.infraguard/policies/<provider>/lib/` - 自定义辅助库

## 常见合规包

### 安全和最佳实践

- `pack:aliyun:security-group-best-practice` - 安全组配置
- `pack:aliyun:resource-protection-best-practice` - 资源保护
- `pack:aliyun:multi-zone-architecture-best-practice` - 高可用性

### 合规标准

- `pack:aliyun:mlps-level-2-pre-check-compliance-pack` - MLPS 二级
- `pack:aliyun:mlps-level-3-pre-check-compliance-pack` - MLPS 三级
- `pack:aliyun:iso-27001-compliance` - ISO 27001
- `pack:aliyun:pci-dss-compliance` - PCI DSS
- `pack:aliyun:soc2-audit-compliance` - SOC 2

### 快速入门

- `pack:aliyun:quick-start-compliance-pack` - 基本安全检查

## 提示

1. **发现策略**：使用 `policy list` 探索可用策略
2. **从小开始**：从 `quick-start-compliance-pack` 开始
3. **先验证**：在使用自定义策略之前始终验证它们
4. **保持更新**：定期运行 `policy update` 获取最新规则

## 下一步

- 了解[编写规则](../development/writing-rules)
- 探索[策略参考](../policies/aliyun/rules)
- 配置[设置](./configuration)

