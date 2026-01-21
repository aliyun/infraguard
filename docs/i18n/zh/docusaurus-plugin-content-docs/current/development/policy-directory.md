---
title: 策略目录结构
---

# 策略目录结构

InfraGuard 支持多个策略来源，并具有清晰的策略加载优先级系统。

## 目录结构

### 标准策略目录结构

策略遵循 provider-first（提供商优先）的目录结构：

```
{策略根目录}/
├── {provider}/
│   ├── rules/
│   │   ├── rule1.rego            # 单个规则
│   │   └── rule2.rego
│   └── packs/
│       ├── pack1.rego            # 合规包
│       └── pack2.rego
```

**示例：**

```
.infraguard/policies/
├── solution/
│   ├── rules/
│   │   ├── metadata-ros-composer-check.rego
│   │   ├── metadata-templatetags-check.rego
│   │   ├── parameter-sensitive-noecho-check.rego
│   │   └── security-group-open-ports-except-whitelist.rego
│   └── packs/
│       └── ros-best-practice.rego
```

## 策略加载优先级

InfraGuard 从多个来源加载策略，优先级如下（从高到低）：

1. **工作区本地策略**：`.infraguard/policies/`（当前工作目录）
2. **用户本地策略**：`~/.infraguard/policies/`（用户主目录）
3. **内嵌策略**：内置于二进制文件中

来自高优先级源的策略将覆盖低优先级源中具有相同 ID 的策略。

## 工作区本地策略

工作区本地策略存储在当前工作目录下的 `.infraguard/policies/` 目录中。这是最高优先级位置，适用于：

- 项目特定的自定义规则和包
- 针对特定项目覆盖内置策略
- 在提升到用户本地或内嵌之前测试新策略

### 使用工作区策略

1. 创建目录结构：

```bash
mkdir -p .infraguard/policies/myprovider/{rules,packs}
```

2. 将自定义规则或包添加到相应目录

3. 列出可用策略：

```bash
infraguard policy list
```

您的工作区策略将以以下 ID 格式显示：`rule:myprovider:rule-name` 或 `pack:myprovider:pack-name`

4. 在扫描中使用它们：

```bash
infraguard scan template.yml -p "pack:myprovider:my-pack"
```

## 用户本地策略

用户本地策略存储在主目录的 `~/.infraguard/policies/` 中。这些策略对您的用户账户下的所有项目可用。

## ID 生成

InfraGuard 根据目录结构自动生成策略 ID：

- **规则**：`rule:{provider}:{rule-id}`
- **包**：`pack:{provider}:{pack-id}`

其中 `{provider}` 派生自父目录名称（例如 `solution`、`aliyun`、`custom`）。


## 下一步

- 学习[编写规则](./writing-rules)
- 学习[编写包](./writing-packs)
- 查看[策略验证](./policy-validation)
