package infraguard.rules.aliyun.redis_instance_release_protection

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "redis-instance-release-protection",
	"name": {
		"en": "Redis Instance Release Protection Enabled",
		"zh": "Redis 实例开启释放保护",
		"ja": "Redis インスタンスの解放保護が有効",
		"de": "Redis-Instanz Freigabeschutz aktiviert",
		"es": "Protección contra Liberación de Instancia Redis Habilitada",
		"fr": "Protection contre la Libération d'Instance Redis Activée",
		"pt": "Proteção contra Liberação de Instância Redis Habilitada",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that Redis instances have release protection enabled.",
		"zh": "确保 Redis 实例开启了释放保护。",
		"ja": "Redis インスタンスで解放保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass Redis-Instanzen Freigabeschutz aktiviert haben.",
		"es": "Garantiza que las instancias Redis tengan protección contra liberación habilitada.",
		"fr": "Garantit que les instances Redis ont la protection contre la libération activée.",
		"pt": "Garante que as instâncias Redis tenham proteção contra liberação habilitada.",
	},
	"reason": {
		"en": "If release protection is not enabled, the Redis instance may be released accidentally, causing service interruption.",
		"zh": "如果未开启释放保护，Redis 实例可能会被意外释放，导致业务中断。",
		"ja": "解放保護が有効になっていない場合、Redis インスタンスが誤って解放され、サービス中断が発生する可能性があります。",
		"de": "Wenn der Freigabeschutz nicht aktiviert ist, kann die Redis-Instanz versehentlich freigegeben werden, was zu Dienstunterbrechungen führt.",
		"es": "Si la protección contra liberación no está habilitada, la instancia Redis puede ser liberada accidentalmente, causando interrupción del servicio.",
		"fr": "Si la protection contre la libération n'est pas activée, l'instance Redis peut être libérée accidentellement, causant une interruption de service.",
		"pt": "Se a proteção contra liberação não estiver habilitada, a instância Redis pode ser liberada acidentalmente, causando interrupção do serviço.",
	},
	"recommendation": {
		"en": "Enable release protection for the Redis instance.",
		"zh": "为 Redis 实例开启释放保护功能。",
		"ja": "Redis インスタンスで解放保護を有効にします。",
		"de": "Aktivieren Sie Freigabeschutz für die Redis-Instanz.",
		"es": "Habilite protección contra liberación para la instancia Redis.",
		"fr": "Activez la protection contre la libération pour l'instance Redis.",
		"pt": "Habilite proteção contra liberação para a instância Redis.",
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeletionProtection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
