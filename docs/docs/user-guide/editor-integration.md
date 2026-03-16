---
title: Editor Integration
---

# Editor Integration

InfraGuard provides editor integration through a built-in Language Server Protocol (LSP) server and a VS Code extension, enabling intelligent editing support for ROS templates.

## VS Code Extension

### Installation

Install the **InfraGuard** extension from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=AlibabaCloudROS.infraguard), or search for "InfraGuard" in the VS Code Extensions panel.

The extension requires the `infraguard` CLI to be installed and available in your PATH. See [Installation](../getting-started/installation) for details.

### Features

#### Auto-Completion

Context-aware completions across the entire template structure:

- **Resource types** — All ALIYUN::* resource type identifiers
- **Properties** — Resource properties with type information, required properties prioritized
- **Intrinsic functions** — `Fn::Join`, `Fn::Sub`, `Fn::Select`, and more
- **Ref/GetAtt targets** — References to parameters, resources, and their attributes
- **Parameter definitions** — Type, Default, AllowedValues, and other parameter properties
- **Top-level sections** — ROSTemplateFormatVersion, Parameters, Resources, Outputs, etc.

When you type a resource type, a `Properties` block with all required keys is auto-inserted.

#### Real-Time Diagnostics

Validates your template as you type:

- Missing or invalid `ROSTemplateFormatVersion`
- Unknown resource types
- Missing required properties
- Type mismatches for property values
- Invalid parameter definitions
- Duplicate YAML keys
- Unknown keys with "Did you mean?" suggestions

#### Hover Documentation

Hover over elements to see contextual documentation:

- **Resource types** — Description and link to official docs
- **Properties** — Type, constraints, whether required or optional, update behavior
- **Intrinsic functions** — Syntax and usage examples

#### Syntax Highlighting

Enhanced syntax highlighting for ROS-specific elements:

- `!Ref`, `Fn::Join`, and other intrinsic functions
- `ALIYUN::*::*` resource type identifiers

### Supported File Types

| Pattern | Detection |
|---------|-----------|
| `*.ros.yaml` / `*.ros.yml` | Automatically recognized as ROS templates |
| `*.ros.json` | Automatically recognized as ROS templates |
| `*.yaml` / `*.json` | Detected via `ROSTemplateFormatVersion` in content |

### Commands

| Command | Description |
|---------|-------------|
| **InfraGuard: Update ROS Schema** | Fetch the latest resource type schema from ROS API |

### Updating ROS Schema

The extension ships with a built-in schema for ROS resource types. To update it with the latest resource type definitions:

1. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Run **InfraGuard: Update ROS Schema**

This requires Alibaba Cloud credentials to be configured. See [`infraguard schema update`](../cli/schema) for credential setup.

## LSP Server

The LSP server can be integrated with any editor that supports the Language Server Protocol.

### Starting the Server

```bash
infraguard lsp
```

The server communicates via stdio (standard input/output).

### Editor Configuration

For editors other than VS Code, configure the LSP client to:

1. Start the server with `infraguard lsp`
2. Use stdio as the transport
3. Associate with YAML and JSON file types

See [`infraguard lsp`](../cli/lsp) for more details.
