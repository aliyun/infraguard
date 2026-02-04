---
title: infraguard update
---

# infraguard update

Actualizar InfraGuard CLI a la última versión o una versión específica.

## Sinopsis

```bash
infraguard update [flags]
```

## Flags

| Flag | Tipo | Descripción |
|------|------|-------------|
| `--check` | boolean | Verificar actualizaciones sin instalar |
| `-f`, `--force` | boolean | Forzar actualización incluso si la versión es actual |
| `--version` | string | Actualizar a una versión específica |

## Ejemplos

### Verificar Actualizaciones

Verificar si hay una nueva versión disponible sin instalar:

```bash
infraguard update --check
```

Salida:
```
Checking for updates...
Current version: 0.4.0
Latest version: 0.5.0
✓ A new version is available: 0.5.0
```

### Actualizar a la Última Versión

Actualizar a la última versión disponible:

```bash
infraguard update
```

Salida:
```
Checking for updates...
Current version: 0.4.0
Latest version: 0.5.0
→ Downloading version 0.5.0...
Downloaded 39.5 MiB / 39.5 MiB (100.0%)
✓ Successfully updated to version 0.5.0!
```

### Actualizar a una Versión Específica

Instalar una versión específica:

```bash
infraguard update --version 0.5.0
```

### Reinstalar Forzadamente la Versión Actual

Reinstalar la versión actual:

```bash
infraguard update --force
# o
infraguard update -f
```
