---
title: infraguard schema
---

# infraguard schema

Manage the ROS resource type schema used by the LSP server.

## Subcommands

### update

Fetch the latest ROS resource type schema from Alibaba Cloud ROS API and save it locally:

```bash
infraguard schema update
```

## Description

The `schema` command manages the ROS resource type schema that the LSP server uses for auto-completion, validation, and hover documentation. The schema contains definitions for all ROS resource types, their properties, types, and constraints.

### Prerequisites

The `schema update` subcommand requires Alibaba Cloud credentials. Configure them using one of:

1. **Environment variables**:
   ```bash
   export ALIBABA_CLOUD_ACCESS_KEY_ID="your-access-key-id"
   export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-access-key-secret"
   ```

2. **Aliyun CLI configuration**:
   ```bash
   aliyun configure
   ```

## Examples

### Update Schema

```bash
infraguard schema update
```

Output:
```
Updating ROS resource type schema...
Schema updated successfully (350 resource types)
```

## Exit Codes

- `0`: Success
- `1`: Error (e.g., missing credentials, network failure)
