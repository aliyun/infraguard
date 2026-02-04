package infraguard.rules.aliyun.ecs_internet_charge_type_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ecs-internet-charge-type-check",
	"severity": "low",
	"name": {
		"en": "ECS Internet Charge Type Check",
		"zh": "ECS 公网带宽计费方式核查",
		"ja": "ECS インターネット課金タイプチェック",
		"de": "ECS Internet-Abrechnungstyp-Prüfung",
		"es": "Verificación de Tipo de Cargo de Internet ECS",
		"fr": "Vérification du Type de Facturation Internet ECS",
		"pt": "Verificação de Tipo de Cobrança de Internet ECS"
	},
	"description": {
		"en": "Ensures ECS instances use the preferred internet charge type.",
		"zh": "确保 ECS 实例使用首选的公网带宽计费方式。",
		"ja": "ECS インスタンスが優先インターネット課金タイプを使用することを確認します。",
		"de": "Stellt sicher, dass ECS-Instanzen den bevorzugten Internet-Abrechnungstyp verwenden.",
		"es": "Garantiza que las instancias ECS usen el tipo de cargo de Internet preferido.",
		"fr": "Garantit que les instances ECS utilisent le type de facturation Internet préféré.",
		"pt": "Garante que as instâncias ECS usem o tipo de cobrança de Internet preferido."
	},
	"reason": {
		"en": "Consistent charge types help in predictable billing and cost management.",
		"zh": "一致的计费方式有助于实现可预测的账单和成本管理。",
		"ja": "一貫した課金タイプにより、予測可能な請求とコスト管理が可能になります。",
		"de": "Konsistente Abrechnungstypen helfen bei vorhersehbarer Abrechnung und Kostenverwaltung.",
		"es": "Los tipos de cargo consistentes ayudan en la facturación predecible y la gestión de costos.",
		"fr": "Des types de facturation cohérents aident à une facturation prévisible et à la gestion des coûts.",
		"pt": "Tipos de cobrança consistentes ajudam na cobrança previsível e no gerenciamento de custos."
	},
	"recommendation": {
		"en": "Set InternetChargeType to 'PayByTraffic'.",
		"zh": "将 InternetChargeType 设置为'PayByTraffic'。",
		"ja": "InternetChargeType を 'PayByTraffic' に設定します。",
		"de": "Setzen Sie InternetChargeType auf 'PayByTraffic'.",
		"es": "Establezca InternetChargeType en 'PayByTraffic'.",
		"fr": "Définissez InternetChargeType sur 'PayByTraffic'.",
		"pt": "Defina InternetChargeType como 'PayByTraffic'."
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"]
}

is_compliant(resource) if {
	charge_type := helpers.get_property(resource, "InternetChargeType", "PayByTraffic")
	charge_type == "PayByTraffic"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "InternetChargeType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
