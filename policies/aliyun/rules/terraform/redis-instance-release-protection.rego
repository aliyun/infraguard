package infraguard.rules.terraform.redis_instance_release_protection

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-instance-release-protection",
	"severity": "medium",
	"name": {
		"en": "Redis Instance Release Protection Enabled",
		"zh": "Redis 实例开启释放保护",
		"ja": "Redis インスタンスの解放保護が有効",
		"de": "Redis-Instanz Freigabeschutz aktiviert",
		"es": "Protección contra Liberación de Instancia Redis Habilitada",
		"fr": "Protection contre la Libération d'Instance Redis Activée",
		"pt": "Proteção contra Liberação de Instância Redis Habilitada"
	},
	"description": {
		"en": "Ensures that Redis instances have release protection enabled.",
		"zh": "确保 Redis 实例开启了释放保护。",
		"ja": "Redis インスタンスで解放保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass Redis-Instanzen Freigabeschutz aktiviert haben.",
		"es": "Garantiza que las instancias Redis tengan protección contra liberación habilitada.",
		"fr": "Garantit que les instances Redis ont la protection contre la libération activée.",
		"pt": "Garante que as instâncias Redis tenham proteção contra liberação habilitada."
	},
	"reason": {
		"en": "If release protection is not enabled, the Redis instance may be released accidentally, causing service interruption.",
		"zh": "如果未开启释放保护，Redis 实例可能会被意外释放，导致业务中断。",
		"ja": "解放保護が有効になっていない場合、Redis インスタンスが誤って解放され、サービス中断が発生する可能性があります。",
		"de": "Wenn der Freigabeschutz nicht aktiviert ist, kann die Redis-Instanz versehentlich freigegeben werden, was zu Dienstunterbrechungen führt.",
		"es": "Si la protección contra liberación no está habilitada, la instancia Redis puede ser liberada accidentalmente, causando interrupción del servicio.",
		"fr": "Si la protection contre la libération n'est pas activée, l'instance Redis peut être libérée accidentellement, causant une interruption de service.",
		"pt": "Se a proteção contra liberação não estiver habilitada, a instância Redis pode ser liberada acidentalmente, causando interrupção do serviço."
	},
	"recommendation": {
		"en": "Set payment_type to \"PrePaid\" to protect the Redis instance from accidental release.",
		"zh": "将 payment_type 设置为 \"PrePaid\" 以保护 Redis 实例不被意外释放。",
		"ja": "Redis インスタンスを誤った解放から保護するために payment_type を \"PrePaid\" に設定します。",
		"de": "Setzen Sie payment_type auf \"PrePaid\", um die Redis-Instanz vor versehentlicher Freigabe zu schützen.",
		"es": "Configure payment_type como \"PrePaid\" para proteger la instancia Redis contra liberación accidental.",
		"fr": "Définissez payment_type sur \"PrePaid\" pour protéger l'instance Redis contre la libération accidentelle.",
		"pt": "Defina payment_type como \"PrePaid\" para proteger a instância Redis contra liberação acidental."
	},
	"resource_types": ["alicloud_kvstore_instance"],
	"iac_type": "terraform"
}

is_protected(resource) if {
	payment_type := tf.get_attribute(resource, "payment_type", "PostPaid")
	payment_type == "PrePaid"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	not is_protected(resource)
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
