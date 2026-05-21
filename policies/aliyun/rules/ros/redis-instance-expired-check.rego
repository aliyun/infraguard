package infraguard.rules.aliyun.redis_instance_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "redis-instance-expired-check",
	"severity": "high",
	"name": {
		"en": "Redis Prepaid Instance Expiration Check",
		"zh": "Redis 预付费实例到期检查",
		"ja": "Redis プリペイドインスタンスの有効期限チェック",
		"de": "Redis Vorausbezahlte Instanz Ablaufprüfung",
		"es": "Verificación de Expiración de Instancia Prepaga Redis",
		"fr": "Vérification d'Expiration d'Instance Prépayée Redis",
		"pt": "Verificação de Expiração de Instância Pré-paga Redis"
	},
	"description": {
		"en": "Prepaid Redis instances should have auto-renewal enabled.",
		"zh": "预付费 Redis 实例应开启自动续费，避免业务中断。",
		"ja": "プリペイド Redis インスタンスは自動更新を有効にする必要があります。",
		"de": "Vorausbezahlte Redis-Instanzen sollten automatische Verlängerung aktiviert haben.",
		"es": "Las instancias Redis prepagas deben tener renovación automática habilitada.",
		"fr": "Les instances Redis prépayées doivent avoir le renouvellement automatique activé.",
		"pt": "Instâncias Redis pré-pagas devem ter renovação automática habilitada."
	},
	"reason": {
		"en": "The prepaid Redis instance does not have auto-renewal enabled.",
		"zh": "预付费 Redis 实例未开启自动续费。",
		"ja": "プリペイド Redis インスタンスで自動更新が有効になっていません。",
		"de": "Die vorausbezahlte Redis-Instanz hat keine automatische Verlängerung aktiviert.",
		"es": "La instancia Redis prepaga no tiene renovación automática habilitada.",
		"fr": "L'instance Redis prépayée n'a pas le renouvellement automatique activé.",
		"pt": "A instância Redis pré-paga não tem renovação automática habilitada."
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid Redis instance by setting AutoRenewDuration.",
		"zh": "通过设置 AutoRenewDuration 为预付费 Redis 实例开启自动续费。",
		"ja": "AutoRenewDuration を設定して、プリペイド Redis インスタンスで自動更新を有効にします。",
		"de": "Aktivieren Sie die automatische Verlängerung für die vorausbezahlte Redis-Instanz, indem Sie AutoRenewDuration setzen.",
		"es": "Habilite la renovación automática para la instancia Redis prepaga estableciendo AutoRenewDuration.",
		"fr": "Activez le renouvellement automatique pour l'instance Redis prépayée en définissant AutoRenewDuration.",
		"pt": "Habilite renovação automática para a instância Redis pré-paga definindo AutoRenewDuration."
	},
	"resource_types": ["ALIYUN::REDIS::Instance"]
}

is_prepaid(resource) if {
	helpers.get_property(resource, "ChargeType", "PostPaid") == "PrePaid"
}

# Redis uses AutoRenewDuration for auto-renewal configuration
is_auto_renew_enabled(resource) if {
	duration := helpers.get_property(resource, "AutoRenewDuration", 0)
	duration > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	is_prepaid(resource)
	not is_auto_renew_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AutoRenewDuration"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
