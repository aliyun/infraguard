---
title: Funções Auxiliares
---

# Funções Auxiliares

O InfraGuard fornece funções auxiliares para simplificar a escrita de políticas.

Importe-as com:
```rego
import data.infraguard.helpers
```

## Funções Disponíveis

| Função | Descrição |
|--------|-----------|
| `resources_by_type(type)` | Obter todos os recursos de um tipo como mapa `{name: resource}` |
| `resource_names_by_type(type)` | Obter todos os nomes de recursos de um tipo como lista |
| `count_resources_by_type(type)` | Contar recursos de um tipo |
| `resource_exists(type)` | Verificar se o tipo de recurso existe |
| `has_property(resource, prop)` | Verificar se a propriedade existe e não é null |
| `get_property(resource, prop, default)` | Obter propriedade com valor padrão |
| `is_true(v)` / `is_false(v)` | Verificar booleano (lida com string "true"/"false") |
| `is_public_cidr(cidr)` | Verificar se CIDR é `0.0.0.0/0` ou `::/0` |
| `includes(list, elem)` | Verificar se o elemento está na lista |

## Exemplos

```rego
# Obter todas as instâncias ECS
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    # Lógica de verificação aqui
}

# Verificar se a propriedade existe
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    not helpers.has_property(resource, "SecurityGroupId")
    # Lógica de violação
}

# Verificar CIDR público
deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
    some rule in resource.Properties.SecurityGroupIngress
    helpers.is_public_cidr(rule.SourceCidrIp)
    # Lógica de violação
}
```

Para mais exemplos, consulte [Escrevendo Regras](./writing-rules).
