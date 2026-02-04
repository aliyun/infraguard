---
title: Gerenciando Políticas
---

# Gerenciando Políticas

Aprenda como descobrir, gerenciar e atualizar políticas no InfraGuard.

## Listando Políticas

### Listar Todas as Políticas

Ver todas as regras e pacotes disponíveis:

```bash
infraguard policy list
```

Isso exibe:
- Todas as regras integradas
- Todos os pacotes de conformidade
- Políticas personalizadas (se houver)

### Filtrar por Provedor

Atualmente, o InfraGuard suporta políticas Aliyun. Versões futuras suportarão provedores adicionais.

## Detalhes das Políticas

### Obter Informações da Regra

Ver informações detalhadas sobre uma regra específica:

```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
```

A saída inclui:
- ID e nome da regra
- Nível de severidade
- Descrição
- Razão da falha
- Recomendação
- Tipos de recursos afetados

### Obter Informações do Pacote

Ver detalhes do pacote de conformidade:

```bash
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

A saída inclui:
- ID e nome do pacote
- Descrição
- Lista de regras incluídas

## Atualizando Políticas

O InfraGuard inclui políticas incorporadas, mas você também pode baixar a biblioteca de políticas mais recente:

```bash
infraguard policy update
```

Isso baixa políticas para `~/.infraguard/policies/`, que tem prioridade sobre as políticas incorporadas.

## Limpando Políticas

Para remover políticas baixadas do seu diretório de usuário:

```bash
infraguard policy clean
```

Este comando:
- Remove todas as políticas de `~/.infraguard/policies/`
- Solicita confirmação por padrão
- Não afeta políticas incorporadas (elas permanecem disponíveis)
- Não afeta políticas do workspace em `.infraguard/policies/`

### Limpeza Forçada (Sem Confirmação)

Para scripts ou ambientes não interativos:

```bash
infraguard policy clean --force
# ou
infraguard policy clean -f
```

### Prioridade de Carregamento de Políticas

O InfraGuard carrega políticas de três fontes com a seguinte prioridade (da mais alta para a mais baixa):

1. **Políticas locais do workspace**: `.infraguard/policies/` (relativo ao diretório de trabalho atual)
2. **Políticas locais do usuário**: `~/.infraguard/policies/`
3. **Políticas incorporadas**: Incorporadas no binário (fallback)

Políticas com o mesmo ID de fontes de maior prioridade substituem as de menor prioridade. Isso permite:
- **Políticas específicas do projeto**: Definir regras personalizadas em `.infraguard/policies/` que são controladas por versão com seu projeto
- **Personalizações do usuário**: Substituir políticas incorporadas globalmente via `~/.infraguard/policies/`
- **Fallback perfeito**: Políticas incorporadas funcionam sem configuração

## Validando Políticas Personalizadas

Antes de usar políticas personalizadas, valide-as:

```bash
infraguard policy validate ./my-custom-rule.rego
```

Isso verifica:
- Sintaxe Rego
- Metadados necessários (`rule_meta` ou `pack_meta`)
- Estrutura adequada da regra deny

### Opções de Validação

```bash
# Validar um único arquivo
infraguard policy validate rule.rego

# Validar um diretório
infraguard policy validate ./policies/

# Especificar idioma de saída
infraguard policy validate rule.rego --lang pt
```

## Formatando Políticas

Formate seus arquivos de políticas usando o formatador OPA:

```bash
# Mostrar saída formatada
infraguard policy format rule.rego

# Escrever alterações de volta ao arquivo
infraguard policy format rule.rego --write

# Mostrar diff das alterações
infraguard policy format rule.rego --diff
```

## Organização de Políticas

### Políticas Incorporadas

Localizadas no binário sob:
- `policies/aliyun/rules/` - Regras individuais
- `policies/aliyun/packs/` - Pacotes de conformidade
- `policies/aliyun/lib/` - Bibliotecas auxiliares

### Políticas Personalizadas

#### Políticas Locais do Workspace (Específicas do Projeto)

Armazene políticas específicas do projeto em seu diretório do projeto:
- `.infraguard/policies/<provider>/rules/` - Regras específicas do projeto
- `.infraguard/policies/<provider>/packs/` - Pacotes específicos do projeto
- `.infraguard/policies/<provider>/lib/` - Bibliotecas auxiliares específicas do projeto

Essas políticas são carregadas automaticamente ao executar comandos InfraGuard de dentro do diretório do projeto e podem ser controladas por versão junto com seus modelos IaC.

#### Políticas Locais do Usuário (Globais)

Armazene políticas personalizadas globais em seu diretório home:
- `~/.infraguard/policies/<provider>/rules/` - Regras personalizadas globais
- `~/.infraguard/policies/<provider>/packs/` - Pacotes personalizados globais
- `~/.infraguard/policies/<provider>/lib/` - Bibliotecas auxiliares personalizadas globais

Essas políticas estão disponíveis para todos os projetos e podem substituir políticas incorporadas.
