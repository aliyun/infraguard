package infraguard.rules.terraform.ecs_instance_type_family_not_deprecated

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-instance-type-family-not-deprecated",
	"severity": "medium",
	"name": {
		"en": "ECS Instance Type Not Deprecated",
		"zh": "ECS 弃用规格族预警",
		"ja": "ECS インスタンスタイプが非推奨ではない",
		"de": "ECS-Instanztyp nicht veraltet",
		"es": "Tipo de Instancia ECS No Deprecado",
		"fr": "Type d'Instance ECS Non Déprécié",
		"pt": "Tipo de Instância ECS Não Depreciado"
	},
	"description": {
		"en": "Ensures ECS instances do not use deprecated or legacy instance types.",
		"zh": "确保 ECS 实例未使用已弃用或陈旧的规格类型。",
		"ja": "ECS インスタンスが非推奨またはレガシーインスタンスタイプを使用していないことを確認します。",
		"de": "Stellt sicher, dass ECS-Instanzen keine veralteten oder Legacy-Instanztypen verwenden.",
		"es": "Garantiza que las instancias ECS no usen tipos de instancia deprecados o heredados.",
		"fr": "Garantit que les instances ECS n'utilisent pas de types d'instance dépréciés ou hérités.",
		"pt": "Garante que as instâncias ECS não usem tipos de instância depreciados ou legados."
	},
	"reason": {
		"en": "Legacy instance types may have lower performance and limited future availability.",
		"zh": "陈旧的实例类型可能性能较低，且未来的可用性受限。",
		"ja": "レガシーインスタンスタイプは、パフォーマンスが低く、将来の可用性が制限される可能性があります。",
		"de": "Legacy-Instanztypen können eine geringere Leistung und begrenzte zukünftige Verfügbarkeit haben.",
		"es": "Los tipos de instancia heredados pueden tener un rendimiento más bajo y disponibilidad futura limitada.",
		"fr": "Les types d'instance hérités peuvent avoir des performances inférieures et une disponibilité future limitée.",
		"pt": "Tipos de instância legados podem ter desempenho mais baixo e disponibilidade futura limitada."
	},
	"recommendation": {
		"en": "Move to newer generation instance types (e.g., g6, c6, r6).",
		"zh": "迁移至新一代实例规格（如 g6, c6, r6）。",
		"ja": "新しい世代のインスタンスタイプ（例：g6、c6、r6）に移行します。",
		"de": "Wechseln Sie zu neueren Instanztyp-Generationen (z. B. g6, c6, r6).",
		"es": "Migre a tipos de instancia de nueva generación (por ejemplo, g6, c6, r6).",
		"fr": "Migrez vers des types d'instance de nouvelle génération (par exemple, g6, c6, r6).",
		"pt": "Migre para tipos de instância de nova geração (por exemplo, g6, c6, r6)."
	},
	"resource_types": ["alicloud_instance"],
	"iac_type": "terraform"
}

violation_for(name) := {
	"id": rule_meta.id,
	"resource_id": sprintf("alicloud_instance.%s", [name]),
	"meta": {
		"severity": rule_meta.severity,
		"reason": rule_meta.reason,
		"recommendation": rule_meta.recommendation,
	},
}

deprecated_prefixes := ["ecs.t1.", "ecs.s1.", "ecs.m1.", "ecs.c1.", "ecs.n1."]

is_deprecated(instance_type) if {
	some prefix in deprecated_prefixes
	startswith(instance_type, prefix)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	instance_type := tf.get_attribute(resource, "instance_type", "")
	not tf.is_unknown(instance_type)
	is_deprecated(instance_type)
	violation := violation_for(name)
}
