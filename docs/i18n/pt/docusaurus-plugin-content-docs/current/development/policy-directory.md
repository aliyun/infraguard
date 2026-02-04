---
title: Estrutura de Diretório de Políticas
---

# Estrutura de Diretório de Políticas

O InfraGuard suporta múltiplas fontes de políticas com um sistema de prioridade claro para carregar políticas.

## Estrutura de Diretório

### Estrutura de Diretório de Políticas Padrão

As políticas seguem uma estrutura de diretório primeiro por provedor:

```
{policy-root}/
├── {provider}/
│   ├── rules/
│   │   ├── rule1.rego            # Regras individuais
│   │   └── rule2.rego
│   └── packs/
│       ├── pack1.rego            # Pacotes de conformidade
│       └── pack2.rego
```

**Exemplo:**

```
.infraguard/policies/
├── solution/
│   ├── rules/
│   │   ├── metadata-ros-composer-check.rego
│   │   ├── metadata-templatetags-check.rego
│   │   ├── parameter-sensitive-noecho-check.rego
│   │   └── security-group-open-ports-except-whitelist.rego
│   └── packs/
│       └── ros-best-practice.rego
```

## Prioridade de Carregamento de Políticas

O InfraGuard carrega políticas de múltiplas fontes com a seguinte prioridade (da mais alta para a mais baixa):

1. **Políticas locais do workspace**: `.infraguard/policies/` (diretório de trabalho atual)
2. **Políticas locais do usuário**: `~/.infraguard/policies/` (diretório home do usuário)
3. **Políticas incorporadas**: Incorporadas no binário

Políticas com o mesmo ID de fontes de maior prioridade substituirão as de fontes de menor prioridade.

## Políticas Locais do Workspace

As políticas locais do workspace são armazenadas no diretório `.infraguard/policies/` dentro do seu diretório de trabalho atual. Este é o local de maior prioridade e ideal para:

- Regras e pacotes personalizados específicos do projeto
- Substituir políticas incorporadas para projetos específicos
- Testar novas políticas antes de promovê-las para usuário-local ou incorporadas

### Usando Políticas do Workspace

1. Crie a estrutura de diretórios:

```bash
mkdir -p .infraguard/policies/myprovider/{rules,packs}
```

2. Adicione suas regras ou pacotes personalizados aos diretórios apropriados

3. Liste as políticas disponíveis:

```bash
infraguard policy list
```

Suas políticas do workspace aparecerão com o formato de ID: `rule:myprovider:rule-name` ou `pack:myprovider:pack-name`

4. Use-as em varreduras:

```bash
infraguard scan template.yml -p "pack:myprovider:my-pack"
```

## Políticas Locais do Usuário

As políticas locais do usuário são armazenadas em `~/.infraguard/policies/` no seu diretório home. Essas políticas estão disponíveis para todos os projetos da sua conta de usuário.

## Geração de ID

O InfraGuard gera automaticamente IDs de políticas com base na estrutura de diretórios:

- **Regras**: `rule:{provider}:{rule-id}`
- **Pacotes**: `pack:{provider}:{pack-id}`

Onde `{provider}` é derivado do nome do diretório pai (ex.: `solution`, `aliyun`, `custom`).

## Próximos Passos

- Aprenda a [Escrever Regras](./writing-rules)
- Aprenda a [Escrever Pacotes](./writing-packs)
- Veja [Validação de Políticas](./policy-validation)
