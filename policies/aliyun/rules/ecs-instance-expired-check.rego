package infraguard.rules.aliyun.ecs_instance_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-instance-expired-check",
	"name": {
		"en": "ECS Prepaid Instance Expiration Check",
		"zh": "ECS 预付费实例到期检查",
		"ja": "ECS プリペイドインスタンスの有効期限チェック",
		"de": "ECS-Vorauszahlungs-Instanz Ablaufprüfung",
		"es": "Verificación de Expiración de Instancia Prepagada ECS",
		"fr": "Vérification d'Expiration d'Instance Prépayée ECS",
		"pt": "Verificação de Expiração de Instância Pré-paga ECS",
	},
	"severity": "high",
	"description": {
		"en": "Prepaid instances should have auto-renewal enabled to avoid service interruption due to expiration.",
		"zh": "预付费实例应开启自动续费，避免出现因费用问题停机。",
		"ja": "プリペイドインスタンスは、有効期限によるサービス中断を避けるために自動更新を有効にする必要があります。",
		"de": "Vorauszahlungs-Instanzen sollten automatische Verlängerung aktiviert haben, um Dienstunterbrechungen aufgrund von Ablauf zu vermeiden.",
		"es": "Las instancias prepagadas deben tener renovación automática habilitada para evitar la interrupción del servicio debido a la expiración.",
		"fr": "Les instances prépayées doivent avoir le renouvellement automatique activé pour éviter l'interruption de service due à l'expiration.",
		"pt": "Instâncias pré-pagas devem ter renovação automática habilitada para evitar interrupção do serviço devido à expiração.",
	},
	"reason": {
		"en": "The prepaid ECS instance does not have auto-renewal enabled.",
		"zh": "预付费 ECS 实例未开启自动续费。",
		"ja": "プリペイド ECS インスタンスで自動更新が有効になっていません。",
		"de": "Die vorausbezahlte ECS-Instanz hat keine automatische Verlängerung aktiviert.",
		"es": "La instancia prepagada ECS no tiene renovación automática habilitada.",
		"fr": "L'instance prépayée ECS n'a pas le renouvellement automatique activé.",
		"pt": "A instância pré-paga ECS não tem renovação automática habilitada.",
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid ECS instance by setting AutoRenew to true.",
		"zh": "通过将 AutoRenew 设置为 true 为预付费 ECS 实例开启自动续费。",
		"ja": "AutoRenew を true に設定して、プリペイド ECS インスタンスで自動更新を有効にします。",
		"de": "Aktivieren Sie die automatische Verlängerung für die vorausbezahlte ECS-Instanz, indem Sie AutoRenew auf true setzen.",
		"es": "Habilite la renovación automática para la instancia prepagada ECS estableciendo AutoRenew en true.",
		"fr": "Activez le renouvellement automatique pour l'instance prépayée ECS en définissant AutoRenew sur true.",
		"pt": "Habilite renovação automática para a instância pré-paga ECS definindo AutoRenew como true.",
	},
	"resource_types": ["ALIYUN::ECS::Instance"],
}

# Check if instance is Prepaid
is_prepaid(resource) if {
	# Check InstanceChargeType
	charge_type := helpers.get_property(resource, "InstanceChargeType", "PostPaid")
	charge_type == "PrePaid"
}

# Check if AutoRenew is enabled
is_auto_renew_enabled(resource) if {
	auto_renew := helpers.get_property(resource, "AutoRenew", false)
	helpers.is_true(auto_renew)
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	is_prepaid(resource)
	not is_auto_renew_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AutoRenew"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
