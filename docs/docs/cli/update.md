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
| `--force` | boolean | Force update even if version is current |
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
Current version: 0.2.0
Latest version: 0.3.0
✓ A new version is available: 0.3.0
```

### Update to Latest Version

Update to the latest available version:

```bash
infraguard update
```

Output:
```
Checking for updates...
Current version: 0.2.0
Latest version: 0.3.0
→ Downloading version 0.3.0...
Downloaded 5.2 MiB / 5.2 MiB (100.0%)
✓ Successfully updated to version 0.3.0!
⚠ Please restart your terminal or run 'hash -r' to use the new version.
```

### Update to Specific Version

Install a specific version:

```bash
infraguard update --version 0.3.0
```

### Force Reinstall Current Version

Reinstall the current version (useful for fixing corrupted installations):

```bash
infraguard update --force
```
