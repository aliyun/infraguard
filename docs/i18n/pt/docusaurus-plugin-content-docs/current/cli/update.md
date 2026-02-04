---
title: infraguard update
---

# infraguard update

Atualizar InfraGuard CLI para a versão mais recente ou uma versão específica.

## Sinopse

```bash
infraguard update [flags]
```

## Flags

| Flag | Tipo | Descrição |
|------|------|-----------|
| `--check` | boolean | Verificar atualizações sem instalar |
| `-f`, `--force` | boolean | Forçar atualização mesmo se a versão for atual |
| `--version` | string | Atualizar para uma versão específica |

## Exemplos

### Verificar Atualizações

Verificar se uma nova versão está disponível sem instalar:

```bash
infraguard update --check
```

Saída:
```
Checking for updates...
Current version: 0.4.0
Latest version: 0.5.0
✓ A new version is available: 0.5.0
```

### Atualizar para a Versão Mais Recente

Atualizar para a versão mais recente disponível:

```bash
infraguard update
```

Saída:
```
Checking for updates...
Current version: 0.4.0
Latest version: 0.5.0
→ Downloading version 0.5.0...
Downloaded 39.5 MiB / 39.5 MiB (100.0%)
✓ Successfully updated to version 0.5.0!
```

### Atualizar para uma Versão Específica

Instalar uma versão específica:

```bash
infraguard update --version 0.5.0
```

### Reinstalar Forçadamente a Versão Atual

Reinstalar a versão atual:

```bash
infraguard update --force
# ou
infraguard update -f
```
