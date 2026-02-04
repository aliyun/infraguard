---
title: infraguard config
---

# infraguard config

Gerenciar configuração do InfraGuard.

## Subcomandos

### set

Definir um valor de configuração:
```bash
infraguard config set lang pt
```

### get

Obter um valor de configuração:
```bash
infraguard config get lang
```

### list

Listar todos os valores de configuração:
```bash
infraguard config list
```

### unset

Remover um valor de configuração:
```bash
infraguard config unset lang
```

## Configurações Disponíveis

- `lang`: Idioma de saída (`en`, `zh`, `es`, `fr`, `de`, `ja`, ou `pt`)

Para mais detalhes, consulte [Configuração](../user-guide/configuration).
