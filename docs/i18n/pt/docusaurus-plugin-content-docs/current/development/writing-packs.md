---
title: Escrevendo Pacotes
---

# Escrevendo Pacotes de Conformidade

Os pacotes agrupam regras relacionadas para facilitar o gerenciamento de políticas.

## Estrutura do Pacote

```rego
package infraguard.packs.aliyun.my_pack

import rego.v1

pack_meta := {
    "id": "my-pack",
    "name": {
        "en": "My Compliance Pack",
        "zh": "我的合规包",
    },
    "description": {
        "en": "Collection of related rules",
        "zh": "相关规则集合",
    },
    "rules": [
        "rule-short-id-1",
        "rule-short-id-2",
        "rule-short-id-3",
    ],
}
```

## Pontos Principais

- Pacote: `infraguard.packs.<provider>.<pack_name_snake_case>`
- Use IDs de regra curtos (sem prefixo `rule:<provider>:`)
- Forneça i18n para nome e descrição

## Localização

Os pacotes podem ser colocados em:
- Workspace-local: `.infraguard/policies/{provider}/packs/`
- Usuário-local: `~/.infraguard/policies/{provider}/packs/`

Veja [Estrutura de Diretório de Políticas](./policy-directory) para detalhes sobre prioridade de carregamento de políticas.

## Próximos Passos

- Veja [Validação de Políticas](./policy-validation)
- Aprenda sobre [Estrutura de Diretório de Políticas](./policy-directory)
- Explore [Funções Auxiliares](./helper-functions)
