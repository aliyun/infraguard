---
title: Integração com Editores
---

# Integração com Editores

O InfraGuard fornece integração com editores por meio de um servidor Language Server Protocol (LSP) integrado e uma extensão VS Code, permitindo suporte inteligente de edição para modelos ROS.

## Extensão VS Code

### Instalação

Instale a extensão **InfraGuard** no [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=aliyun.infraguard) ou pesquise por "InfraGuard" no painel de extensões do VS Code.

A extensão requer que o CLI `infraguard` esteja instalado e disponível no seu PATH. Consulte [Instalação](../getting-started/installation) para detalhes.

### Recursos

#### Auto-Completar

Completar contextual em toda a estrutura do modelo:

- **Tipos de recursos** — Todos os identificadores de tipos de recursos ALIYUN::*
- **Propriedades** — Propriedades de recursos com informações de tipo, propriedades obrigatórias priorizadas
- **Funções intrínsecas** — `Fn::Join`, `Fn::Sub`, `Fn::Select` e mais
- **Alvos Ref/GetAtt** — Referências a parâmetros, recursos e seus atributos
- **Definições de parâmetros** — Type, Default, AllowedValues e outras propriedades de parâmetros
- **Seções de nível superior** — ROSTemplateFormatVersion, Parameters, Resources, Outputs, etc.

Quando você digita um tipo de recurso, um bloco `Properties` com todas as chaves obrigatórias é inserido automaticamente.

#### Diagnósticos em Tempo Real

Valida seu modelo enquanto você digita:

- `ROSTemplateFormatVersion` ausente ou inválido
- Tipos de recursos desconhecidos
- Propriedades obrigatórias ausentes
- Incompatibilidades de tipo para valores de propriedades
- Definições de parâmetros inválidas
- Chaves YAML duplicadas
- Chaves desconhecidas com sugestões "Você quis dizer?"

#### Documentação ao Passar o Mouse

Passe o mouse sobre os elementos para ver documentação contextual:

- **Tipos de recursos** — Descrição e link para documentação oficial
- **Propriedades** — Tipo, restrições, obrigatório ou opcional, comportamento de atualização
- **Funções intrínsecas** — Sintaxe e exemplos de uso

#### Destaque de Sintaxe

Destaque de sintaxe aprimorado para elementos específicos do ROS:

- `!Ref`, `Fn::Join` e outras funções intrínsecas
- Identificadores de tipos de recursos `ALIYUN::*::*`

### Tipos de Arquivo Suportados

| Pattern | Detection |
|---------|-----------|
| `*.ros.yaml` / `*.ros.yml` | Reconhecido automaticamente como modelos ROS |
| `*.ros.json` | Reconhecido automaticamente como modelos ROS |
| `*.yaml` / `*.json` | Detectado via `ROSTemplateFormatVersion` no conteúdo |

### Comandos

| Command | Description |
|---------|-------------|
| **InfraGuard: Update ROS Schema** | Buscar o esquema mais recente de tipos de recursos na API ROS |

### Atualizando o Esquema ROS

A extensão inclui um esquema integrado para tipos de recursos ROS. Para atualizá-lo com as definições mais recentes:

1. Abra a Paleta de Comandos (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Execute **InfraGuard: Update ROS Schema**

Isso requer que as credenciais da Alibaba Cloud estejam configuradas. Consulte [`infraguard schema update`](../cli/schema) para configuração de credenciais.

## Servidor LSP

O servidor LSP pode ser integrado com qualquer editor que suporte o Language Server Protocol.

### Iniciando o Servidor

```bash
infraguard lsp
```

O servidor se comunica via stdio (entrada/saída padrão).

### Configuração do Editor

Para editores diferentes do VS Code, configure o cliente LSP para:

1. Iniciar o servidor com `infraguard lsp`
2. Usar stdio como transporte
3. Associar aos tipos de arquivo YAML e JSON

Consulte [`infraguard lsp`](../cli/lsp) para mais detalhes.
