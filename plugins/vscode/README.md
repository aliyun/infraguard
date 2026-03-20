# InfraGuard - ROS Template Support

InfraGuard provides intelligent editing support for Alibaba Cloud ROS (Resource Orchestration Service) templates in VS Code.

## Features

### Auto-Completion

Context-aware completions across the entire template structure — resource types, properties, intrinsic functions, Ref/GetAtt targets, parameter definitions, Mappings keys, and more. Required properties are prioritized, and a `Properties` block with required keys is auto-inserted when you type a resource type.

### Real-Time Diagnostics

Validates your template as you type — checks format version, resource types, required properties, type mismatches, parameter definitions, Mappings structure, and duplicate YAML keys. Unknown keys trigger "Did you mean?" suggestions.

### Hover Documentation

Hover over resource types, properties, or intrinsic functions to see descriptions, type info, constraints, and whether a property is required or updatable.

### Go to Definition

Jump to definitions from references:

- **Ref/GetAtt** — Jump from `!Ref`, `Ref`, or `Fn::GetAtt` to parameter, locals, or resource definitions
- **AssociationPropertyMetadata** — Jump from `${Name}` placeholders in metadata to parameter definitions

Use `Ctrl+Click` (or `Cmd+Click` on macOS) or press `F12`.

### Syntax Highlighting

Enhanced syntax highlighting for ROS-specific elements like `!Ref`, `Fn::Join`, and `ALIYUN::*::*` resource type identifiers.

## Supported File Types

- `*.ros.yaml` / `*.ros.yml` / `*.ros.json` — Automatically recognized as ROS templates
- Regular `.yaml` / `.json` files — Detected via `ROSTemplateFormatVersion` in content

## Commands

- **InfraGuard: Update ROS Schema** — Fetch the latest resource type schema from ROS API
