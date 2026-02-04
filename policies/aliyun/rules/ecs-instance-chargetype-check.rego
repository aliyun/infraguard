package infraguard.rules.aliyun.ecs_instance_chargetype_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ecs-instance-chargetype-check",
	"name": {
		"en": "ECS Instance Charge Type Check",
		"zh": "ECS 实例付费类型核查",
		"ja": "ECS インスタンスの課金タイプチェック",
		"de": "ECS-Instanz-Gebührentyp-Prüfung",
		"es": "Verificación de Tipo de Cargo de Instancia ECS",
		"fr": "Vérification du Type de Facturation de l'Instance ECS",
		"pt": "Verificação de Tipo de Cobrança da Instância ECS"
	},
	"severity": "low",
	"description": {
		"en": "Ensures ECS instances use the authorized charge type.",
		"zh": "确保 ECS 实例使用授权的付费类型。",
		"ja": "ECS インスタンスが承認された課金タイプを使用していることを確認します。",
		"de": "Stellt sicher, dass ECS-Instanzen den autorisierten Gebührentyp verwenden.",
		"es": "Garantiza que las instancias ECS usen el tipo de cargo autorizado.",
		"fr": "Garantit que les instances ECS utilisent le type de facturation autorisé.",
		"pt": "Garante que as instâncias ECS usem o tipo de cobrança autorizado."
	},
	"reason": {
		"en": "Enforcing specific charge types (e.g., PostPaid) aligns with organizational budget policies.",
		"zh": "强制执行特定的付费类型（如后付费）符合组织预算政策。",
		"ja": "特定の課金タイプ（例：PostPaid）を強制することは、組織の予算ポリシーと一致します。",
		"de": "Die Durchsetzung spezifischer Gebührentypen (z. B. PostPaid) entspricht den organisatorischen Budgetrichtlinien.",
		"es": "Hacer cumplir tipos de cargo específicos (por ejemplo, PostPaid) se alinea con las políticas presupuestarias organizacionales.",
		"fr": "L'application de types de facturation spécifiques (par exemple, PostPaid) s'aligne sur les politiques budgétaires organisationnelles.",
		"pt": "Aplicar tipos de cobrança específicos (por exemplo, PostPaid) está alinhado com as políticas orçamentárias organizacionais."
	},
	"recommendation": {
		"en": "Set InstanceChargeType to 'PostPaid'.",
		"zh": "将 InstanceChargeType 设置为'PostPaid'。",
		"ja": "InstanceChargeType を 'PostPaid' に設定します。",
		"de": "Setzen Sie InstanceChargeType auf 'PostPaid'.",
		"es": "Establezca InstanceChargeType en 'PostPaid'.",
		"fr": "Définissez InstanceChargeType sur 'PostPaid'.",
		"pt": "Defina InstanceChargeType como 'PostPaid'."
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

is_compliant(resource) if {
	charge_type := helpers.get_property(resource, "InstanceChargeType", "PostPaid")
	charge_type == "PostPaid"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "InstanceChargeType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
