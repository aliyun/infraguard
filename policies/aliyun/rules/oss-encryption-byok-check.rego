package infraguard.rules.aliyun.oss_encryption_byok_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "oss-encryption-byok-check",
	"name": {
		"en": "OSS Bucket BYOK Encryption Check",
		"zh": "OSS 存储空间使用自定义 KMS 密钥加密",
		"ja": "OSS バケット BYOK 暗号化チェック",
		"de": "OSS-Bucket BYOK-Verschlüsselungsprüfung",
		"es": "Verificación de Cifrado BYOK de Bucket OSS",
		"fr": "Vérification du Chiffrement BYOK de Bucket OSS",
		"pt": "Verificação de Criptografia BYOK de Bucket OSS",
	},
	"severity": "medium",
	"description": {
		"en": "OSS buckets should use customer-managed KMS keys (BYOK - Bring Your Own Key) for encryption. This provides better control over encryption keys and meets compliance requirements.",
		"zh": "OSS 存储空间应使用客户管理的 KMS 密钥（BYOK - 自带密钥）进行加密。这提供了对加密密钥的更好控制并满足合规要求。",
		"ja": "OSS バケットは、暗号化にカスタマー管理の KMS キー（BYOK - Bring Your Own Key）を使用する必要があります。これにより、暗号化キーに対するより良い制御が提供され、コンプライアンス要件を満たします。",
		"de": "OSS-Buckets sollten kundenseitig verwaltete KMS-Schlüssel (BYOK - Bring Your Own Key) für die Verschlüsselung verwenden. Dies bietet eine bessere Kontrolle über Verschlüsselungsschlüssel und erfüllt Compliance-Anforderungen.",
		"es": "Los buckets OSS deben usar claves KMS administradas por el cliente (BYOK - Bring Your Own Key) para el cifrado. Esto proporciona un mejor control sobre las claves de cifrado y cumple con los requisitos de cumplimiento.",
		"fr": "Les buckets OSS doivent utiliser des clés KMS gérées par le client (BYOK - Bring Your Own Key) pour le chiffrement. Cela offre un meilleur contrôle sur les clés de chiffrement et répond aux exigences de conformité.",
		"pt": "Buckets OSS devem usar chaves KMS gerenciadas pelo cliente (BYOK - Bring Your Own Key) para criptografia. Isso fornece melhor controle sobre chaves de criptografia e atende aos requisitos de conformidade.",
	},
	"reason": {
		"en": "The OSS bucket does not use customer-managed KMS keys for encryption, which may not meet compliance requirements for key management.",
		"zh": "OSS 存储空间未使用客户管理的 KMS 密钥进行加密，可能无法满足密钥管理的合规要求。",
		"ja": "OSS バケットが暗号化にカスタマー管理の KMS キーを使用していないため、キー管理のコンプライアンス要件を満たさない可能性があります。",
		"de": "Der OSS-Bucket verwendet keine kundenseitig verwalteten KMS-Schlüssel für die Verschlüsselung, was möglicherweise nicht den Compliance-Anforderungen für die Schlüsselverwaltung entspricht.",
		"es": "El bucket OSS no usa claves KMS administradas por el cliente para el cifrado, lo que puede no cumplir con los requisitos de cumplimiento para la gestión de claves.",
		"fr": "Le bucket OSS n'utilise pas de clés KMS gérées par le client pour le chiffrement, ce qui peut ne pas répondre aux exigences de conformité pour la gestion des clés.",
		"pt": "O bucket OSS não usa chaves KMS gerenciadas pelo cliente para criptografia, o que pode não atender aos requisitos de conformidade para gerenciamento de chaves.",
	},
	"recommendation": {
		"en": "Configure the OSS bucket to use customer-managed KMS keys by setting SSEAlgorithm to KMS and specifying a KMSMasterKeyID in ServerSideEncryptionConfiguration.",
		"zh": "通过将 SSEAlgorithm 设置为 KMS 并在 ServerSideEncryptionConfiguration 中指定 KMSMasterKeyID，将 OSS 存储空间配置为使用客户管理的 KMS 密钥。",
		"ja": "SSEAlgorithm を KMS に設定し、ServerSideEncryptionConfiguration で KMSMasterKeyID を指定して、OSS バケットをカスタマー管理の KMS キーを使用するように設定します。",
		"de": "Konfigurieren Sie den OSS-Bucket so, dass er kundenseitig verwaltete KMS-Schlüssel verwendet, indem Sie SSEAlgorithm auf KMS setzen und eine KMSMasterKeyID in ServerSideEncryptionConfiguration angeben.",
		"es": "Configure el bucket OSS para usar claves KMS administradas por el cliente estableciendo SSEAlgorithm en KMS y especificando un KMSMasterKeyID en ServerSideEncryptionConfiguration.",
		"fr": "Configurez le bucket OSS pour utiliser des clés KMS gérées par le client en définissant SSEAlgorithm sur KMS et en spécifiant un KMSMasterKeyID dans ServerSideEncryptionConfiguration.",
		"pt": "Configure o bucket OSS para usar chaves KMS gerenciadas pelo cliente definindo SSEAlgorithm como KMS e especificando um KMSMasterKeyID em ServerSideEncryptionConfiguration.",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	not uses_byok_encryption(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ServerSideEncryptionConfiguration"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

uses_byok_encryption(resource) if {
	helpers.has_property(resource, "ServerSideEncryptionConfiguration")
	sse_config := resource.Properties.ServerSideEncryptionConfiguration
	sse_config.SSEAlgorithm == "KMS"
	sse_config.KMSMasterKeyID != null
}
