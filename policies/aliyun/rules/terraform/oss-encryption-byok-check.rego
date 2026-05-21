package infraguard.rules.terraform.oss_encryption_byok_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-encryption-byok-check",
	"severity": "medium",
	"name": {
		"en": "OSS Bucket BYOK Encryption Check",
		"zh": "OSS 存储空间使用自定义 KMS 密钥加密",
		"ja": "OSS バケット BYOK 暗号化チェック",
		"de": "OSS-Bucket BYOK-Verschlüsselungsprüfung",
		"es": "Verificación de Cifrado BYOK de Bucket OSS",
		"fr": "Vérification du Chiffrement BYOK de Bucket OSS",
		"pt": "Verificação de Criptografia BYOK de Bucket OSS"
	},
	"description": {
		"en": "Ensures OSS bucket uses KMS encryption with a customer-managed key (BYOK).",
		"zh": "确保 OSS 存储桶使用客户自定义 KMS 密钥 (BYOK) 加密。",
		"ja": "OSS バケットは、暗号化にカスタマー管理の KMS キー（BYOK - Bring Your Own Key）を使用する必要があります。これにより、暗号化キーに対するより良い制御が提供され、コンプライアンス要件を満たします。",
		"de": "OSS-Buckets sollten kundenseitig verwaltete KMS-Schlüssel (BYOK - Bring Your Own Key) für die Verschlüsselung verwenden. Dies bietet eine bessere Kontrolle über Verschlüsselungsschlüssel und erfüllt Compliance-Anforderungen.",
		"es": "Los buckets OSS deben usar claves KMS administradas por el cliente (BYOK - Bring Your Own Key) para el cifrado. Esto proporciona un mejor control sobre las claves de cifrado y cumple con los requisitos de cumplimiento.",
		"fr": "Les buckets OSS doivent utiliser des clés KMS gérées par le client (BYOK - Bring Your Own Key) pour le chiffrement. Cela offre un meilleur contrôle sur les clés de chiffrement et répond aux exigences de conformité.",
		"pt": "Buckets OSS devem usar chaves KMS gerenciadas pelo cliente (BYOK - Bring Your Own Key) para criptografia. Isso fornece melhor controle sobre chaves de criptografia e atende aos requisitos de conformidade."
	},
	"reason": {
		"en": "The OSS bucket does not use a customer-managed KMS key for encryption.",
		"zh": "OSS 存储桶未使用客户自定义 KMS 密钥加密。",
		"ja": "OSS バケットが暗号化にカスタマー管理の KMS キーを使用していないため、キー管理のコンプライアンス要件を満たさない可能性があります。",
		"de": "Der OSS-Bucket verwendet keine kundenseitig verwalteten KMS-Schlüssel für die Verschlüsselung, was möglicherweise nicht den Compliance-Anforderungen für die Schlüsselverwaltung entspricht.",
		"es": "El bucket OSS no usa claves KMS administradas por el cliente para el cifrado, lo que puede no cumplir con los requisitos de cumplimiento para la gestión de claves.",
		"fr": "Le bucket OSS n'utilise pas de clés KMS gérées par le client pour le chiffrement, ce qui peut ne pas répondre aux exigences de conformité pour la gestion des clés.",
		"pt": "O bucket OSS não usa chaves KMS gerenciadas pelo cliente para criptografia, o que pode não atender aos requisitos de conformidade para gerenciamento de chaves."
	},
	"recommendation": {
		"en": "Set sse_algorithm to 'KMS' and specify a kms_master_key_id in server_side_encryption_rule.",
		"zh": "将 sse_algorithm 设置为 'KMS' 并在 server_side_encryption_rule 中指定 kms_master_key_id。",
		"ja": "SSEAlgorithm を KMS に設定し、ServerSideEncryptionConfiguration で KMSMasterKeyID を指定して、OSS バケットをカスタマー管理の KMS キーを使用するように設定します。",
		"de": "Konfigurieren Sie den OSS-Bucket so, dass er kundenseitig verwaltete KMS-Schlüssel verwendet, indem Sie SSEAlgorithm auf KMS setzen und eine KMSMasterKeyID in ServerSideEncryptionConfiguration angeben.",
		"es": "Configure el bucket OSS para usar claves KMS administradas por el cliente estableciendo SSEAlgorithm en KMS y especificando un KMSMasterKeyID en ServerSideEncryptionConfiguration.",
		"fr": "Configurez le bucket OSS pour utiliser des clés KMS gérées par le client en définissant SSEAlgorithm sur KMS et en spécifiant un KMSMasterKeyID dans ServerSideEncryptionConfiguration.",
		"pt": "Configure o bucket OSS para usar chaves KMS gerenciadas pelo cliente definindo SSEAlgorithm como KMS e especificando um KMSMasterKeyID em ServerSideEncryptionConfiguration."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

is_byok_encrypted(resource) if {
	sse_rule := tf.get_attribute(resource, "server_side_encryption_rule", {})
	algorithm := object.get(sse_rule, "sse_algorithm", "")
	algorithm == "KMS"
	key_id := object.get(sse_rule, "kms_master_key_id", "")
	not tf.is_unknown(key_id)
	key_id != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	not is_byok_encrypted(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_oss_bucket.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
