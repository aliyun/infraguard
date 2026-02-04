---
title: Escrevendo Regras
---

# Escrevendo Regras Personalizadas

Aprenda como escrever regras de conformidade personalizadas para o InfraGuard.

## Estrutura da Regra

As regras são escritas em Rego (linguagem Open Policy Agent) com a seguinte estrutura:

```rego
package infraguard.rules.aliyun.my_custom_rule

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "my-custom-rule",
    "name": {
        "en": "My Custom Rule",
        "zh": "我的自定义规则",
    },
    "severity": "high",
    "description": {
        "en": "Checks for custom compliance requirement",
        "zh": "检查自定义合规要求",
    },
    "reason": {
        "en": "Resource does not meet requirement",
        "zh": "资源不符合要求",
    },
    "recommendation": {
        "en": "Configure resource properly",
        "zh": "正确配置资源",
    },
    "resource_types": ["ALIYUN::ECS::Instance"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    # Sua lógica de conformidade aqui
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "SomeProperty"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    # Sua lógica de verificação de conformidade aqui
}
```

## Componentes Principais

### Nome do Pacote

Deve seguir o formato: `infraguard.rules.<provider>.<rule_name_snake_case>`

**Nota**: Use underscores, não hífens nos nomes de pacotes.

### Metadados da Regra

Campos obrigatórios:
- `id`: Identificador da regra (kebab-case)
- `name`: Nome de exibição (mapa i18n)
- `severity`: `high`, `medium`, ou `low`
- `description`: O que a regra verifica
- `reason`: Por que falhou
- `recommendation`: Como corrigir
- `resource_types`: Tipos de recursos afetados (opcional)

### Regra Deny

Deve retornar resultados com:
- `id`: ID da regra
- `resource_id`: Nome do recurso do modelo
- `violation_path`: Caminho para a propriedade problemática
- `meta`: Severidade, razão, recomendação

## Funções Auxiliares

Veja [Funções Auxiliares](./helper-functions) para funções utilitárias disponíveis.

## Validação

Sempre valide suas regras:

```bash
infraguard policy validate my-rule.rego
```

## Depuração de Regras

Use declarações print para depurar suas regras durante o desenvolvimento:

```rego
deny contains result if {
    print("Checking resource:", name)
    print("Resource properties:", object.keys(resource.Properties))
    # Sua lógica aqui
}
```

Veja [Depuração de Políticas](./debugging-policies) para técnicas completas de depuração.

## Próximos Passos

- Aprenda [Depuração de Políticas](./debugging-policies)
- Veja [Validação de Políticas](./policy-validation)
- Aprenda a [Escrever Pacotes](./writing-packs)
- Aprenda sobre [Estrutura de Diretório de Políticas](./policy-directory)
- Explore [Funções Auxiliares](./helper-functions)
