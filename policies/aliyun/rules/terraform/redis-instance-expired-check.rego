package infraguard.rules.terraform.redis_instance_expired_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "Enable auto-renewal by setting auto_renew to true for the prepaid Redis instance.",
		"zh": "通过将 auto_renew 设置为 true 为预付费 Redis 实例开启自动续费。",
		"ja": "プリペイド Redis インスタンスで auto_renew を true に設定して自動更新を有効にします。",
		"de": "Aktivieren Sie die automatische Verlängerung, indem Sie auto_renew auf true für die vorausbezahlte Redis-Instanz setzen.",
		"es": "Habilite la renovación automática configurando auto_renew como true para la instancia Redis prepaga.",
		"fr": "Activez le renouvellement automatique en définissant auto_renew sur true pour l'instance Redis prépayée.",
		"pt": "Habilite renovação automática definindo auto_renew como true para a instância Redis pré-paga."
	},
	"resource_types": ["alicloud_kvstore_instance"],
	"iac_type": "terraform"
}

is_prepaid(resource) if {
	payment_type := tf.get_attribute(resource, "payment_type", "PostPaid")
	payment_type == "PrePaid"
}

is_auto_renew_enabled(resource) if {
	auto_renew := tf.get_attribute(resource, "auto_renew", false)
	auto_renew == true
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	is_prepaid(resource)
	not is_auto_renew_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_kvstore_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
