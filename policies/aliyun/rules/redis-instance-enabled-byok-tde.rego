package infraguard.rules.aliyun.redis_instance_enabled_byok_tde

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "redis-instance-enabled-byok-tde",
	"name": {
		"en": "Redis Instance BYOK TDE Enabled",
		"zh": "Redis 实例开启 BYOK TDE 加密",
		"ja": "Redis インスタンスで BYOK TDE が有効",
		"de": "Redis-Instanz BYOK TDE aktiviert",
		"es": "TDE BYOK de Instancia Redis Habilitado",
		"fr": "TDE BYOK d'Instance Redis Activé",
		"pt": "TDE BYOK de Instância Redis Habilitado",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that Redis instances have Transparent Data Encryption (TDE) enabled using Bring Your Own Key (BYOK).",
		"zh": "确保 Redis 实例已使用自带密钥(BYOK)开启了透明数据加密(TDE)。",
		"ja": "Redis インスタンスで Bring Your Own Key (BYOK) を使用して透過的データ暗号化（TDE）が有効になっていることを確認します。",
		"de": "Stellt sicher, dass Redis-Instanzen Transparent Data Encryption (TDE) mit Bring Your Own Key (BYOK) aktiviert haben.",
		"es": "Garantiza que las instancias Redis tengan Transparent Data Encryption (TDE) habilitado usando Bring Your Own Key (BYOK).",
		"fr": "Garantit que les instances Redis ont Transparent Data Encryption (TDE) activé en utilisant Bring Your Own Key (BYOK).",
		"pt": "Garante que as instâncias Redis tenham Transparent Data Encryption (TDE) habilitado usando Bring Your Own Key (BYOK).",
	},
	"reason": {
		"en": "TDE protects data at rest, and BYOK allows you to maintain control over the encryption keys.",
		"zh": "TDE 可保护静态数据，而 BYOK 允许您保持对加密密钥的控制。",
		"ja": "TDE は保存データを保護し、BYOK により暗号化キーに対する制御を維持できます。",
		"de": "TDE schützt ruhende Daten, und BYOK ermöglicht es Ihnen, die Kontrolle über die Verschlüsselungsschlüssel zu behalten.",
		"es": "TDE protege los datos en reposo, y BYOK le permite mantener el control sobre las claves de cifrado.",
		"fr": "TDE protège les données au repos, et BYOK vous permet de maintenir le contrôle sur les clés de chiffrement.",
		"pt": "TDE protege dados em repouso, e BYOK permite manter controle sobre as chaves de criptografia.",
	},
	"recommendation": {
		"en": "Enable TDE for the Redis instance using a KMS key.",
		"zh": "使用 KMS 密钥为 Redis 实例开启 TDE。",
		"ja": "KMS キーを使用して Redis インスタンスで TDE を有効にします。",
		"de": "Aktivieren Sie TDE für die Redis-Instanz mit einem KMS-Schlüssel.",
		"es": "Habilite TDE para la instancia Redis usando una clave KMS.",
		"fr": "Activez TDE pour l'instance Redis en utilisant une clé KMS.",
		"pt": "Habilite TDE para a instância Redis usando uma chave KMS.",
	},
	"resource_types": ["ALIYUN::Redis::DBInstance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::Redis::DBInstance")

	# Conceptual check for TDE
	not helpers.has_property(resource, "TDEStatus")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
