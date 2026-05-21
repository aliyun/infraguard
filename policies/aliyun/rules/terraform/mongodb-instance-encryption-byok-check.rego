package infraguard.rules.terraform.mongodb_instance_encryption_byok_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mongodb-instance-encryption-byok-check",
	"severity": "high",
	"name": {
		"en": "MongoDB Instance TDE with Custom KMS Key",
		"zh": "MongoDB 实例使用自定义 KMS 密钥进行 TDE 加密",
		"ja": "MongoDB インスタンスが TDE にカスタムキーを使用",
		"de": "MongoDB-Instanz verwendet benutzerdefinierten Schlüssel für TDE",
		"es": "La Instancia MongoDB Usa Clave Personalizada para TDE",
		"fr": "L'Instance MongoDB Utilise une Clé Personnalisée pour TDE",
		"pt": "A Instância MongoDB Usa Chave Personalizada para TDE"
	},
	"description": {
		"en": "MongoDB instances should have TDE enabled with a customer-managed KMS encryption key (BYOK).",
		"zh": "MongoDB 实例应启用 TDE 并使用客户管理的 KMS 加密密钥（BYOK）。",
		"ja": "MongoDB インスタンスが透過的データ暗号化（TDE）にカスタム KMS キーを使用していることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen benutzerdefinierte KMS-Schlüssel für Transparent Data Encryption (TDE) verwenden.",
		"es": "Garantiza que las instancias MongoDB usen claves KMS personalizadas para Cifrado Transparente de Datos (TDE).",
		"fr": "Garantit que les instances MongoDB utilisent des clés KMS personnalisées pour le Chiffrement Transparent des Données (TDE).",
		"pt": "Garante que as instâncias MongoDB usem chaves KMS personalizadas para Criptografia Transparente de Dados (TDE)."
	},
	"reason": {
		"en": "The MongoDB instance does not have TDE enabled with a custom KMS key.",
		"zh": "MongoDB 实例未启用 TDE 或未使用自定义 KMS 密钥。",
		"ja": "TDE に顧客管理キーを使用することで、暗号化をより適切に制御し、データセキュリティを強化できます。",
		"de": "Die Verwendung von kundenseitig verwalteten Schlüsseln für TDE bietet eine bessere Kontrolle über die Verschlüsselung und verbessert die Datensicherheit.",
		"es": "Usar claves administradas por el cliente para TDE proporciona un mejor control sobre el cifrado y mejora la seguridad de los datos.",
		"fr": "L'utilisation de clés gérées par le client pour TDE offre un meilleur contrôle sur le chiffrement et améliore la sécurité des données.",
		"pt": "Usar chaves gerenciadas pelo cliente para TDE fornece melhor controle sobre a criptografia e melhora a segurança dos dados."
	},
	"recommendation": {
		"en": "Set tde_status to 'enabled' and specify an encryption_key.",
		"zh": "将 tde_status 设置为 'enabled' 并指定 encryption_key。",
		"ja": "MongoDB インスタンスでカスタム KMS キーを使用して TDE を有効にします。",
		"de": "Aktivieren Sie TDE mit einem benutzerdefinierten KMS-Schlüssel für die MongoDB-Instanz.",
		"es": "Habilite TDE con una clave KMS personalizada para la instancia MongoDB.",
		"fr": "Activez TDE avec une clé KMS personnalisée pour l'instance MongoDB.",
		"pt": "Habilite TDE com uma chave KMS personalizada para a instância MongoDB."
	},
	"resource_types": ["alicloud_mongodb_instance"],
	"iac_type": "terraform"
}

is_tde_with_byok(resource) if {
	tf.get_attribute(resource, "tde_status", "") == "enabled"
	key := tf.get_attribute(resource, "encryption_key", "")
	key != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mongodb_instance")
	not is_tde_with_byok(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mongodb_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
