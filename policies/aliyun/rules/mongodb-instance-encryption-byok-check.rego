package infraguard.rules.aliyun.mongodb_instance_encryption_byok_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mongodb-instance-encryption-byok-check",
	"name": {
		"en": "MongoDB Instance Uses Custom Key for TDE",
		"zh": "使用自定义密钥为 MongoDB 设置透明数据加密 TDE",
		"ja": "MongoDB インスタンスが TDE にカスタムキーを使用",
		"de": "MongoDB-Instanz verwendet benutzerdefinierten Schlüssel für TDE",
		"es": "La Instancia MongoDB Usa Clave Personalizada para TDE",
		"fr": "L'Instance MongoDB Utilise une Clé Personnalisée pour TDE",
		"pt": "A Instância MongoDB Usa Chave Personalizada para TDE",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures MongoDB instances use custom KMS keys for Transparent Data Encryption (TDE).",
		"zh": "确保 MongoDB 实例使用自定义 KMS 密钥进行透明数据加密（TDE）。",
		"ja": "MongoDB インスタンスが透過的データ暗号化（TDE）にカスタム KMS キーを使用していることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen benutzerdefinierte KMS-Schlüssel für Transparent Data Encryption (TDE) verwenden.",
		"es": "Garantiza que las instancias MongoDB usen claves KMS personalizadas para Cifrado Transparente de Datos (TDE).",
		"fr": "Garantit que les instances MongoDB utilisent des clés KMS personnalisées pour le Chiffrement Transparent des Données (TDE).",
		"pt": "Garante que as instâncias MongoDB usem chaves KMS personalizadas para Criptografia Transparente de Dados (TDE).",
	},
	"reason": {
		"en": "Using customer-managed keys for TDE provides better control over encryption and enhances data security.",
		"zh": "使用客户管理密钥进行 TDE 可以更好地控制加密并增强数据安全性。",
		"ja": "TDE に顧客管理キーを使用することで、暗号化をより適切に制御し、データセキュリティを強化できます。",
		"de": "Die Verwendung von kundenseitig verwalteten Schlüsseln für TDE bietet eine bessere Kontrolle über die Verschlüsselung und verbessert die Datensicherheit.",
		"es": "Usar claves administradas por el cliente para TDE proporciona un mejor control sobre el cifrado y mejora la seguridad de los datos.",
		"fr": "L'utilisation de clés gérées par le client pour TDE offre un meilleur contrôle sur le chiffrement et améliore la sécurité des données.",
		"pt": "Usar chaves gerenciadas pelo cliente para TDE fornece melhor controle sobre a criptografia e melhora a segurança dos dados.",
	},
	"recommendation": {
		"en": "Enable TDE with a custom KMS key for the MongoDB instance.",
		"zh": "为 MongoDB 实例启用 TDE 并使用自定义 KMS 密钥。",
		"ja": "MongoDB インスタンスでカスタム KMS キーを使用して TDE を有効にします。",
		"de": "Aktivieren Sie TDE mit einem benutzerdefinierten KMS-Schlüssel für die MongoDB-Instanz.",
		"es": "Habilite TDE con una clave KMS personalizada para la instancia MongoDB.",
		"fr": "Activez TDE avec une clé KMS personnalisée pour l'instance MongoDB.",
		"pt": "Habilite TDE com uma chave KMS personalizada para a instância MongoDB.",
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

# Check if instance is Serverless type (not applicable)
is_serverless(resource) if {
	tags := helpers.get_property(resource, "Tags", [])
	some tag in tags
	tag.Key == "InstanceType"
	tag.Value == "Serverless"
}

is_serverless(resource) if {
	instance_class := helpers.get_property(resource, "DBInstanceClass", "")
	contains(lower(instance_class), "serverless")
}

# Check if TDE is enabled with custom key
is_compliant(resource) if {
	not is_serverless(resource)
	tde_enabled := helpers.get_property(resource, "TDEStatus", false)
	tde_enabled == true
	kms_key_id := helpers.get_property(resource, "EncryptionKey", "")
	kms_key_id != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_serverless(resource)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TDEStatus"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
