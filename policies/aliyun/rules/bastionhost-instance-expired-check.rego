package infraguard.rules.aliyun.bastionhost_instance_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "bastionhost-instance-expired-check",
	"severity": "high",
	"name": {
		"en": "BastionHost Instance Expiration Check",
		"zh": "堡垒机实例到期检查",
		"ja": "BastionHost インスタンス有効期限チェック",
		"de": "BastionHost-Instanz Ablaufprüfung",
		"es": "Verificación de Expiración de Instancia BastionHost",
		"fr": "Vérification d'Expiration d'Instance BastionHost",
		"pt": "Verificação de Expiração de Instância BastionHost"
	},
	"description": {
		"en": "Prepaid BastionHost instances should have auto-renewal enabled.",
		"zh": "预付费堡垒机实例应开启自动续费，避免业务中断。",
		"ja": "プリペイド BastionHost インスタンスで自動更新が有効になっている必要があります。",
		"de": "Vorausbezahlte BastionHost-Instanzen sollten automatische Verlängerung aktiviert haben.",
		"es": "Las instancias BastionHost prepagadas deben tener renovación automática habilitada.",
		"fr": "Les instances BastionHost prépayées doivent avoir le renouvellement automatique activé.",
		"pt": "As instâncias BastionHost pré-pagas devem ter renovação automática habilitada."
	},
	"reason": {
		"en": "The prepaid BastionHost instance does not have auto-renewal enabled.",
		"zh": "预付费堡垒机实例未开启自动续费。",
		"ja": "プリペイド BastionHost インスタンスで自動更新が有効になっていません。",
		"de": "Die vorausbezahlte BastionHost-Instanz hat keine automatische Verlängerung aktiviert.",
		"es": "La instancia BastionHost prepagada no tiene renovación automática habilitada.",
		"fr": "L'instance BastionHost prépayée n'a pas le renouvellement automatique activé.",
		"pt": "A instância BastionHost pré-paga não tem renovação automática habilitada."
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid BastionHost instance by setting AutoRenew to true.",
		"zh": "通过将 AutoRenew 设置为 true 为预付费堡垒机实例开启自动续费。",
		"ja": "AutoRenew を true に設定して、プリペイド BastionHost インスタンスの自動更新を有効にします。",
		"de": "Aktivieren Sie die automatische Verlängerung für die vorausbezahlte BastionHost-Instanz, indem Sie AutoRenew auf true setzen.",
		"es": "Habilite la renovación automática para la instancia BastionHost prepagada estableciendo AutoRenew en true.",
		"fr": "Activez le renouvellement automatique pour l'instance BastionHost prépayée en définissant AutoRenew sur true.",
		"pt": "Habilite a renovação automática para a instância BastionHost pré-paga definindo AutoRenew como true."
	},
	"resource_types": ["ALIYUN::BastionHost::Instance"]
}

is_prepaid(resource) if {
	# Check if Period is set, as it implies subscription
	helpers.has_property(resource, "Period")
}

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
