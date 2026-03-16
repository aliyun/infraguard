---
title: infraguard lsp
---

# infraguard lsp

Start the ROS Language Server Protocol (LSP) server for editor integration.

## Synopsis

```bash
infraguard lsp [flags]
```

## Description

The `lsp` command starts a Language Server Protocol (LSP) server that communicates via standard I/O (stdio). It provides intelligent editing support for ROS templates in editors like VS Code, including:

- **Auto-completion** — Resource types, properties, intrinsic functions, Ref/GetAtt targets
- **Real-time diagnostics** — Format version, resource types, required properties, type mismatches
- **Hover documentation** — Descriptions, type info, constraints for resources and properties

The LSP server supports both YAML and JSON template formats.

## Flags

| Flag | Type | Description |
|------|------|-------------|
| `--stdio` | bool | Use stdio transport (default, accepted for editor compatibility) |

## Examples

### Start LSP Server

```bash
infraguard lsp
```

### Start with Explicit stdio Flag

```bash
infraguard lsp --stdio
```

## Editor Integration

The LSP server is typically started automatically by editor extensions. For VS Code, install the [InfraGuard extension](https://marketplace.visualstudio.com/items?itemName=AlibabaCloudROS.infraguard) which handles LSP lifecycle management.

For more details, see [Editor Integration](../user-guide/editor-integration).

## Exit Codes

- `0`: Server exited normally
