---
title: 编辑器集成
---

# 编辑器集成

InfraGuard 通过内置的 Language Server Protocol (LSP) 服务器和 VS Code 扩展提供编辑器集成，为 ROS 模板提供智能编辑支持。

## VS Code 扩展

### 安装

从 [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=AlibabaCloudROS.infraguard) 安装 **InfraGuard** 扩展，或在 VS Code 扩展面板中搜索 "InfraGuard"。

### 功能

#### 自动补全

在整个模板结构中提供上下文感知的补全：

- **资源类型** — 所有 ALIYUN::* 资源类型标识符
- **属性** — 带类型信息的资源属性，必填属性优先
- **内建函数** — `Fn::Join`、`Fn::Sub`、`Fn::Select` 等
- **Ref/GetAtt 目标** — 对参数、资源及其属性的引用
- **参数定义** — Type、Default、AllowedValues 及其他参数属性
- **顶层节** — ROSTemplateFormatVersion、Parameters、Resources、Outputs 等

输入资源类型时，会自动插入包含所有必填键的 `Properties` 块。

#### 实时诊断

在输入时验证模板：

- 缺失或无效的 `ROSTemplateFormatVersion`
- 未知的资源类型
- 缺失的必填属性
- 属性值的类型不匹配
- 无效的参数定义
- 重复的 YAML 键
- 未知键并提供「您是否指的是？」建议

#### 悬停文档

将鼠标悬停在元素上可查看上下文文档：

- **资源类型** — 描述及官方文档链接
- **属性** — 类型、约束、必填或可选、更新行为
- **内建函数** — 语法及使用示例

#### 转到定义

从引用跳转到定义：

- **Ref 目标** — 从 `!Ref` 或 `Ref` 跳转到参数或资源定义
- **GetAtt 目标** — 从 `Fn::GetAtt` 跳转到资源定义
- **资源引用** — 从属性引用导航到资源定义
- **AssociationPropertyMetadata** — 从 metadata 中的 `${Name}` 占位符跳转到参数定义

在引用上使用 `Ctrl+点击`（macOS 上 `Cmd+点击`）或按 `F12` 跳转到其定义。

#### 语法高亮

针对 ROS 特定元素的增强语法高亮：

- `!Ref`、`Fn::Join` 及其他内建函数
- `ALIYUN::*::*` 资源类型标识符

### 支持的文件类型

| Pattern | Detection |
|---------|-----------|
| `*.ros.yaml` / `*.ros.yml` | 自动识别为 ROS 模板 |
| `*.ros.json` | 自动识别为 ROS 模板 |
| `*.yaml` / `*.json` | 通过内容中的 `ROSTemplateFormatVersion` 检测 |

### 命令

| Command | Description |
|---------|-------------|
| **InfraGuard: Update ROS Schema** | 从 ROS API 获取最新的资源类型架构 |

### 更新 ROS 架构

该扩展内置 ROS 资源类型架构。要使用最新的资源类型定义进行更新：

1. 打开命令面板（`Ctrl+Shift+P` / `Cmd+Shift+P`）
2. 运行 **InfraGuard: Update ROS Schema**

需要配置阿里云凭据。有关凭据设置，请参阅 [`infraguard schema update`](../cli/schema)。

## LSP 服务器

LSP 服务器可与支持 Language Server Protocol 的任何编辑器集成。

### 启动服务器

```bash
infraguard lsp
```

服务器通过 stdio（标准输入/输出）进行通信。

### 编辑器配置

对于 VS Code 以外的编辑器，请将 LSP 客户端配置为：

1. 使用 `infraguard lsp` 启动服务器
2. 使用 stdio 作为传输方式
3. 与 YAML 和 JSON 文件类型关联

更多详情请参阅 [`infraguard lsp`](../cli/lsp)。
