---
title: infraguard schema
---

# infraguard schema

Gerencie o esquema de tipos de recursos ROS usado pelo servidor LSP.

## Subcomandos

### update

Obtenha o esquema mais recente de tipos de recursos ROS da API ROS da Alibaba Cloud e salve-o localmente:

```bash
infraguard schema update
```

## Descrição

O comando `schema` gerencia o esquema de tipos de recursos ROS que o servidor LSP usa para preenchimento automático, validação e documentação ao passar o cursor. O esquema contém definições de todos os tipos de recursos ROS, suas propriedades, tipos e restrições.

### Pré-requisitos

O subcomando `schema update` requer credenciais da Alibaba Cloud. Configure-as usando uma das opções:

1. **Variáveis de ambiente**:
   ```bash
   export ALIBABA_CLOUD_ACCESS_KEY_ID="your-access-key-id"
   export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-access-key-secret"
   ```

2. **Configuração do Aliyun CLI**:
   ```bash
   aliyun configure
   ```

## Exemplos

### Atualizar o Esquema

```bash
infraguard schema update
```

Saída:
```
Updating ROS resource type schema...
Schema updated successfully (350 resource types)
```

## Códigos de Saída

- `0`: Sucesso
- `1`: Erro (ex.: credenciais ausentes, falha de rede)
