package infraguard.rules.terraform.bastionhost_instance_expired_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "Enable auto-renewal for the prepaid BastionHost instance by setting renewal_status to AutoRenewal.",
		"zh": "通过将 renewal_status 设置为 AutoRenewal 为预付费堡垒机实例开启自动续费。",
		"ja": "renewal_status を AutoRenewal に設定して、プリペイド BastionHost インスタンスの自動更新を有効にします。",
		"de": "Aktivieren Sie die automatische Verlängerung für die vorausbezahlte BastionHost-Instanz, indem Sie renewal_status auf AutoRenewal setzen.",
		"es": "Habilite la renovación automática para la instancia BastionHost prepagada estableciendo renewal_status en AutoRenewal.",
		"fr": "Activez le renouvellement automatique pour l'instance BastionHost prépayée en définissant renewal_status sur AutoRenewal.",
		"pt": "Habilite a renovação automática para a instância BastionHost pré-paga definindo renewal_status como AutoRenewal."
	},
	"resource_types": ["alicloud_bastionhost_instance"],
	"iac_type": "terraform"
}

is_prepaid(resource) if {
	period := tf.get_attribute(resource, "period", "")
	not tf.is_unknown(period)
	period != ""
}

is_auto_renew_enabled(resource) if {
	renewal_status := tf.get_attribute(resource, "renewal_status", "")
	not tf.is_unknown(renewal_status)
	renewal_status == "AutoRenewal"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_bastionhost_instance")
	is_prepaid(resource)
	not is_auto_renew_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_bastionhost_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
