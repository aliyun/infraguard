package infraguard.rules.aliyun.redis_instance_tls_version_check

import rego.v1

import data.infraguard.helpers

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
		"en": "Enable SSL with recommended TLS version for Redis instance.",
		"zh": "为 Redis 实例启用 SSL 并使用推荐的 TLS 版本。",
		"ja": "Redis インスタンスで推奨 TLS バージョンで SSL を有効にします。",
		"de": "Aktivieren Sie SSL mit empfohlener TLS-Version für Redis-Instanz.",
		"es": "Habilite SSL con la versión TLS recomendada para la instancia Redis.",
		"fr": "Activez SSL avec la version TLS recommandée pour l'instance Redis.",
		"pt": "Habilite SSL com a versão TLS recomendada para a instância Redis."
	},
	"resource_types": ["ALIYUN::REDIS::Instance"]
}

is_compliant(resource) if {
	ssl_enabled := helpers.get_property(resource, "SSLEnabled", "Disable")
	ssl_enabled == "Enable"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SSLEnabled"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
