package infraguard.rules.aliyun.rds_instance_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rds-instance-expired-check",
	"severity": "high",
	"name": {
		"en": "RDS Prepaid Instance Expiration Check",
		"zh": "RDS 预付费实例到期检查",
		"ja": "RDS プリペイドインスタンスの有効期限チェック",
		"de": "RDS Vorausbezahlte Instanz Ablaufprüfung",
		"es": "Verificación de Expiración de Instancia Prepaga RDS",
		"fr": "Vérification d'Expiration d'Instance Prépayée RDS",
		"pt": "Verificação de Expiração de Instância Pré-paga RDS"
	},
	"description": {
		"en": "Prepaid RDS instances should have auto-renewal enabled.",
		"zh": "预付费 RDS 实例应开启自动续费，避免业务中断。",
		"ja": "プリペイド RDS インスタンスは自動更新を有効にする必要があります。",
		"de": "Vorausbezahlte RDS-Instanzen sollten automatische Verlängerung aktiviert haben.",
		"es": "Las instancias RDS prepagas deben tener renovación automática habilitada.",
		"fr": "Les instances RDS prépayées doivent avoir le renouvellement automatique activé.",
		"pt": "Instâncias RDS pré-pagas devem ter renovação automática habilitada."
	},
	"reason": {
		"en": "The prepaid RDS instance does not have auto-renewal enabled.",
		"zh": "预付费 RDS 实例未开启自动续费。",
		"ja": "プリペイド RDS インスタンスで自動更新が有効になっていません。",
		"de": "Die vorausbezahlte RDS-Instanz hat keine automatische Verlängerung aktiviert.",
		"es": "La instancia RDS prepaga no tiene renovación automática habilitada.",
		"fr": "L'instance RDS prépayée n'a pas le renouvellement automatique activé.",
		"pt": "A instância RDS pré-paga não tem renovação automática habilitada."
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid RDS instance by setting AutoRenew to true.",
		"zh": "通过将 AutoRenew 设置为 true 为预付费 RDS 实例开启自动续费。",
		"ja": "AutoRenew を true に設定して、プリペイド RDS インスタンスで自動更新を有効にします。",
		"de": "Aktivieren Sie die automatische Verlängerung für die vorausbezahlte RDS-Instanz, indem Sie AutoRenew auf true setzen.",
		"es": "Habilite la renovación automática para la instancia RDS prepaga estableciendo AutoRenew en true.",
		"fr": "Activez le renouvellement automatique pour l'instance RDS prépayée en définissant AutoRenew sur true.",
		"pt": "Habilite renovação automática para a instância RDS pré-paga definindo AutoRenew como true."
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"]
}

is_prepaid(resource) if {
	helpers.get_property(resource, "PayType", "Postpaid") == "Prepaid"
}

# RDS AutoRenew property name is AutoRenew
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
