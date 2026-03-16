---
title: infraguard lsp
---

# infraguard lsp

启动 ROS 语言服务器协议 (LSP) 服务器，用于编辑器集成。

## 概要

```bash
infraguard lsp [选项]
```

## 说明

`lsp` 命令启动一个通过标准 I/O (stdio) 进行通信的语言服务器协议 (LSP) 服务器。它为 VS Code 等编辑器中的 ROS 模板提供智能编辑支持，包括：

- **自动补全** — 资源类型、属性、内置函数、Ref/GetAtt 目标
- **实时诊断** — 格式版本、资源类型、必需属性、类型不匹配
- **悬停文档** — 资源和属性的描述、类型信息、约束

LSP 服务器支持 YAML 和 JSON 两种模板格式。

## 选项

| 选项 | 类型 | 说明 |
|------|------|-------------|
| `--stdio` | bool | 使用 stdio 传输（默认，为编辑器兼容性而接受） |

## 示例

### 启动 LSP 服务器

```bash
infraguard lsp
```

### 使用显式 stdio 标志启动

```bash
infraguard lsp --stdio
```

## 编辑器集成

LSP 服务器通常由编辑器扩展自动启动。对于 VS Code，请安装 [InfraGuard 扩展](https://marketplace.visualstudio.com/items?itemName=AlibabaCloudROS.infraguard)，该扩展负责 LSP 生命周期管理。

有关更多详细信息，请参阅[编辑器集成](../user-guide/editor-integration)。

## 退出代码

- `0`: 服务器正常退出
