---
title: infraguard update
---

# infraguard update

Update InfraGuard CLI to the latest version or a specific version.

## Synopsis

```bash
infraguard update [flags]
```

## Flags

| Flag | Type | Description |
|------|------|-------------|
| `--check` | boolean | Check for updates without installing |
| `-f`, `--force` | boolean | Force update even if version is current |
| `--version` | string | Update to a specific version |

## Examples

### Check for Updates

Check if a new version is available without installing:

```bash
infraguard update --check
```

Output:
```
Checking for updates...
Current version: 0.4.0
Latest version: 0.5.0
✓ A new version is available: 0.5.0
```

### Update to Latest Version

Update to the latest available version:

```bash
infraguard update
```

Output:
```
Checking for updates...
Current version: 0.4.0
Latest version: 0.5.0
→ Downloading version 0.5.0...
Downloaded 39.5 MiB / 39.5 MiB (100.0%)
✓ Successfully updated to version 0.5.0!
```

### Update to Specific Version

Install a specific version:

```bash
infraguard update --version 0.5.0
```

### Force Reinstall Current Version

Reinstall the current version:

```bash
infraguard update --force
# or
infraguard update -f
```
