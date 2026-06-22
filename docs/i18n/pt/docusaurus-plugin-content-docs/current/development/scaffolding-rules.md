---
title: Estrutura e Teste de Regras
---

# Estrutura e Teste de Regras Personalizadas

O InfraGuard vem com mais de 600 regras integradas, mas a maioria das equipes também tem
requisitos de conformidade privados (convenções de nomenclatura, tags de custo obrigatórias, regras de CIDR internas…).
Esta página mostra o caminho rápido para criar e verificar suas próprias regras sem sair
da CLI.

O ciclo é: **`policy new` → editar → `policy test` → `scan`**.

## 1. Gerar a estrutura de uma regra

```bash
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance \
  --name-en "ECS instance must have owner tag" \
  --name-zh "ECS 实例必须包含 owner 标签"
```

Isso gera um esqueleto pronto para edição sob `./policies` (substitua com `--dir`):

```
policies/
├── rules/
│   ├── ros/ecs-instance-must-have-owner-tag.rego
│   └── terraform/ecs-instance-must-have-owner-tag.rego
└── testdata/aliyun/rules/ecs-instance-must-have-owner-tag/
    ├── ros/{compliant.yaml, violation.yaml}
    └── terraform/{compliant/main.tf, violation/main.tf}
```

O `.rego` gerado pré-preenche o bloco `rule_meta` (id, severity, placeholders de nome em
7 idiomas, tipos de recurso) e uma regra `deny` mínima com marcadores `TODO`.
Regras personalizadas podem importar livremente os helpers integrados (`data.infraguard.helpers`,
`data.infraguard.helpers.terraform`) — o InfraGuard os injeta automaticamente quando
você escaneia ou testa. Consulte [Funções Auxiliares](./helper-functions) e
[Escrevendo Regras](./writing-rules).

## 2. Implementar a lógica

Edite os arquivos gerados e substitua os marcadores `TODO`. Por exemplo, a regra ROS:

```rego
is_compliant(resource) if {
	helpers.has_tags(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Tags"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
```

Depois torne as fixtures significativas: a fixture `compliant` deve satisfazer a regra
(por exemplo, incluir a tag `owner`) e a fixture `violation` deve quebrá-la.

## Testando Regras

`infraguard policy test` avalia cada regra contra suas fixtures usando o mesmo
mecanismo que o `scan`:

- Fixtures `compliant` não devem produzir **nenhuma** violação da regra.
- Fixtures `violation` devem produzir **pelo menos uma**.

```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule ecs-instance-must-have-owner-tag
infraguard policy test --dir ./policies --iac terraform
infraguard policy test --dir ./policies --format json   # legível por máquina, para CI
```

Exemplo de saída:

```
RULE                              CASE                  STATUS
ecs-instance-must-have-owner-tag  ros/compliant         ✓ pass
ecs-instance-must-have-owner-tag  ros/violation         ✓ pass
ecs-instance-must-have-owner-tag  terraform/compliant   ✓ pass
ecs-instance-must-have-owner-tag  terraform/violation   ✓ pass

1 rules, 4 cases: 4 passed, 0 failed
```

Códigos de saída: `0` todos passaram, `1` um caso falhou, `2` nenhuma fixture encontrada (substitua com
`--allow-empty`). Isso torna o `policy test` um gate de CI natural para um repositório de regras personalizadas.

## 3. Usar a regra em uma varredura

Aponte o `scan` para o seu diretório de políticas:

```bash
infraguard scan -p ./policies my-template.yaml
```

## Dicas

- Use `infraguard policy validate ./policies` para verificações estáticas (sintaxe,
  completude do `rule_meta`) antes que o `policy test` execute os testes de comportamento.
- Mantenha as implementações ROS e Terraform da mesma regra sob o mesmo ID;
  elas compartilham os metadados da regra e são mescladas automaticamente.
- Consulte a [referência da CLI policy](../cli/policy) para a lista completa de flags.
