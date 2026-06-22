---
title: Generar y Probar Reglas
---

# Generar y Probar Reglas Personalizadas

InfraGuard incluye más de 600 reglas integradas, pero la mayoría de los equipos
también tienen requisitos de cumplimiento privados (convenciones de nomenclatura,
etiquetas de costo obligatorias, reglas de CIDR internas…). Esta página muestra la
vía rápida para crear y verificar sus propias reglas sin salir de la CLI.

El ciclo es: **`policy new` → editar → `policy test` → `scan`**.

## 1. Generar una regla

```bash
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance \
  --name-en "ECS instance must have owner tag" \
  --name-zh "ECS 实例必须包含 owner 标签"
```

Esto genera un esqueleto listo para editar bajo `./policies` (anúlelo con `--dir`):

```
policies/
├── rules/
│   ├── ros/ecs-instance-must-have-owner-tag.rego
│   └── terraform/ecs-instance-must-have-owner-tag.rego
└── testdata/aliyun/rules/ecs-instance-must-have-owner-tag/
    ├── ros/{compliant.yaml, violation.yaml}
    └── terraform/{compliant/main.tf, violation/main.tf}
```

El `.rego` generado rellena previamente el bloque `rule_meta` (id, severidad,
marcadores de posición de nombre en 7 idiomas, tipos de recursos) y una regla
`deny` mínima con marcadores `TODO`. Las reglas personalizadas pueden importar
libremente los ayudantes integrados (`data.infraguard.helpers`,
`data.infraguard.helpers.terraform`) — InfraGuard los inyecta automáticamente
cuando escanea o prueba. Consulte [Funciones Auxiliares](./helper-functions) y
[Escribir Reglas](./writing-rules).

## 2. Implementar la lógica

Edite los archivos generados y reemplace los marcadores `TODO`. Por ejemplo, la
regla ROS:

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

Luego haga que las fixtures sean significativas: la fixture `compliant` debe
satisfacer la regla (por ejemplo, incluir la etiqueta `owner`) y la fixture
`violation` debe romperla.

## Probar Reglas {#testing-rules}

`infraguard policy test` evalúa cada regla contra sus fixtures usando el mismo
motor que `scan`:

- Las fixtures `compliant` no deben producir **ninguna** violación de la regla.
- Las fixtures `violation` deben producir **al menos una**.

```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule ecs-instance-must-have-owner-tag
infraguard policy test --dir ./policies --iac terraform
infraguard policy test --dir ./policies --format json   # machine-readable, for CI
```

Salida de ejemplo:

```
RULE                              CASE                  STATUS
ecs-instance-must-have-owner-tag  ros/compliant         ✓ pass
ecs-instance-must-have-owner-tag  ros/violation         ✓ pass
ecs-instance-must-have-owner-tag  terraform/compliant   ✓ pass
ecs-instance-must-have-owner-tag  terraform/violation   ✓ pass

1 rules, 4 cases: 4 passed, 0 failed
```

Códigos de salida: `0` todas pasan, `1` un caso falló, `2` no se encontraron
fixtures (anúlelo con `--allow-empty`). Esto hace de `policy test` una puerta de CI
natural para un repositorio de reglas personalizadas.

## 3. Usar la regla en un escaneo

Apunte `scan` a su directorio de políticas:

```bash
infraguard scan -p ./policies my-template.yaml
```

## Consejos

- Use `infraguard policy validate ./policies` para comprobaciones estáticas
  (sintaxis, integridad de `rule_meta`) antes de que `policy test` ejecute las
  pruebas de comportamiento.
- Mantenga las implementaciones ROS y Terraform de la misma regla bajo el mismo ID;
  comparten los metadatos de la regla y se fusionan automáticamente.
- Consulte la [referencia de CLI de policy](../cli/policy) para la lista completa de
  flags.
