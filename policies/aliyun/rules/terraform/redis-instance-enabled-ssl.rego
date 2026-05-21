package infraguard.rules.terraform.redis_instance_enabled_ssl

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-instance-enabled-ssl",
	"severity": "medium",
	"name": {
		"en": "Redis Instance SSL Enabled",
		"zh": "Redis 实例开启 SSL 加密",
		"ja": "Redis インスタンスで SSL が有効",
		"de": "Redis-Instanz SSL aktiviert",
		"es": "SSL de Instancia Redis Habilitado",
		"fr": "SSL d'Instance Redis Activé",
		"pt": "SSL de Instância Redis Habilitado"
	},
	"description": {
		"en": "Ensures Redis instances have SSL encryption enabled.",
		"zh": "确保 Redis 实例开启了 SSL 加密。",
		"ja": "Redis インスタンスで SSL 暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass Redis-Instanzen SSL-Verschlüsselung aktiviert haben.",
		"es": "Garantiza que las instancias Redis tengan cifrado SSL habilitado.",
		"fr": "Garantit que les instances Redis ont le chiffrement SSL activé.",
		"pt": "Garante que as instâncias Redis tenham criptografia SSL habilitada."
	},
	"reason": {
		"en": "SSL encryption protects Redis data in transit from being intercepted.",
		"zh": "SSL 加密保护传输中的 Redis 数据不被截获。",
		"ja": "SSL 暗号化により、送信中の Redis データが傍受から保護されます。",
		"de": "SSL-Verschlüsselung schützt Redis-Daten während der Übertragung vor Abfangen.",
		"es": "El cifrado SSL protege los datos Redis en tránsito contra interceptación.",
		"fr": "Le chiffrement SSL protège les données Redis en transit contre l'interception.",
		"pt": "A criptografia SSL protege dados Redis em trânsito contra interceptação."
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
