package infraguard.rules.terraform.redis_instance_tls_version_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-instance-tls-version-check",
	"severity": "medium",
	"name": {
		"en": "Redis Instance TLS Version Check",
		"zh": "Redis 实例开启 SSL 并使用指定的 TLS 版本",
		"ja": "Redis インスタンス TLS バージョンチェック",
		"de": "Redis-Instanz TLS-Versionsprüfung",
		"es": "Verificación de Versión TLS de Instancia Redis",
		"fr": "Vérification de Version TLS d'Instance Redis",
		"pt": "Verificação de Versão TLS de Instância Redis"
	},
	"description": {
		"en": "Ensures Redis instance has SSL enabled with acceptable TLS version.",
		"zh": "确保 Redis 实例开启 SSL 且使用的 TLS 版本在可接受范围内。",
		"ja": "Redis インスタンスで許容可能な TLS バージョンで SSL が有効になっていることを確認します。",
		"de": "Stellt sicher, dass die Redis-Instanz SSL mit einer akzeptablen TLS-Version aktiviert hat.",
		"es": "Garantiza que la instancia Redis tenga SSL habilitado con una versión TLS aceptable.",
		"fr": "Garantit que l'instance Redis a SSL activé avec une version TLS acceptable.",
		"pt": "Garante que a instância Redis tenha SSL habilitado com uma versão TLS aceitável."
	},
	"reason": {
		"en": "Using strong TLS versions ensures secure communication.",
		"zh": "使用强 TLS 版本确保通信安全。",
		"ja": "強力な TLS バージョンを使用することで、安全な通信が確保されます。",
		"de": "Die Verwendung starker TLS-Versionen gewährleistet sichere Kommunikation.",
		"es": "Usar versiones TLS fuertes garantiza una comunicación segura.",
		"fr": "L'utilisation de versions TLS fortes garantit une communication sécurisée.",
		"pt": "Usar versões TLS fortes garante comunicação segura."
	},
	"recommendation": {
		"en": "Enable SSL by setting ssl_enable to \"Enable\" for the Redis instance.",
		"zh": "通过将 ssl_enable 设置为 \"Enable\" 为 Redis 实例开启 SSL。",
		"ja": "Redis インスタンスで ssl_enable を \"Enable\" に設定して SSL を有効にします。",
		"de": "Aktivieren Sie SSL, indem Sie ssl_enable auf \"Enable\" für die Redis-Instanz setzen.",
		"es": "Habilite SSL configurando ssl_enable como \"Enable\" para la instancia Redis.",
		"fr": "Activez SSL en définissant ssl_enable sur \"Enable\" pour l'instance Redis.",
		"pt": "Habilite SSL definindo ssl_enable como \"Enable\" para a instância Redis."
	},
	"resource_types": ["alicloud_kvstore_instance"],
	"iac_type": "terraform"
}

is_ssl_enabled(resource) if {
	ssl_enable := tf.get_attribute(resource, "ssl_enable", "Disable")
	ssl_enable == "Enable"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	not is_ssl_enabled(resource)
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
