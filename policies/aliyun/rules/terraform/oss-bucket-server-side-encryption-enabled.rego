package infraguard.rules.terraform.oss_bucket_server_side_encryption_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-bucket-server-side-encryption-enabled",
	"severity": "high",
	"name": {
		"en": "OSS Bucket Server-Side Encryption Enabled",
		"zh": "OSS 存储空间开启服务端加密",
		"ja": "OSS バケットのサーバー側暗号化が有効",
		"de": "OSS-Bucket-Serverseitige-Verschlüsselung aktiviert",
		"es": "Cifrado del Lado del Servidor de Bucket OSS Habilitado",
		"fr": "Chiffrement Côté Serveur de Bucket OSS Activé",
		"pt": "Criptografia do Lado do Servidor de Bucket OSS Habilitada"
	},
	"description": {
		"en": "Ensures OSS bucket has server-side encryption enabled.",
		"zh": "确保 OSS 存储桶开启了服务端加密。",
		"ja": "OSS バケットは、保存データを保護するためにサーバー側暗号化を有効にする必要があります。サーバー側暗号化は KMS または AES256 を使用して OSS に保存されたデータを暗号化します。",
		"de": "OSS-Buckets sollten serverseitige Verschlüsselung aktiviert haben, um ruhende Daten zu schützen. Die serverseitige Verschlüsselung verwendet KMS oder AES256, um in OSS gespeicherte Daten zu verschlüsseln.",
		"es": "Los buckets OSS deben tener cifrado del lado del servidor habilitado para proteger los datos en reposo. El cifrado del lado del servidor usa KMS o AES256 para cifrar datos almacenados en OSS.",
		"fr": "Les buckets OSS doivent avoir le chiffrement côté serveur activé pour protéger les données au repos. Le chiffrement côté serveur utilise KMS ou AES256 pour chiffrer les données stockées dans OSS.",
		"pt": "Buckets OSS devem ter criptografia do lado do servidor habilitada para proteger dados em repouso. A criptografia do lado do servidor usa KMS ou AES256 para criptografar dados armazenados no OSS."
	},
	"reason": {
		"en": "The OSS bucket does not have server-side encryption enabled.",
		"zh": "OSS 存储桶未开启服务端加密。",
		"ja": "OSS バケットでサーバー側暗号化が有効になっていないため、機密データが不正アクセスにさらされる可能性があります。",
		"de": "Der OSS-Bucket hat keine serverseitige Verschlüsselung aktiviert, was sensible Daten unbefugtem Zugriff aussetzen kann.",
		"es": "El bucket OSS no tiene cifrado del lado del servidor habilitado, lo que puede exponer datos sensibles a acceso no autorizado.",
		"fr": "Le bucket OSS n'a pas le chiffrement côté serveur activé, ce qui peut exposer des données sensibles à un accès non autorisé.",
		"pt": "O bucket OSS não tem criptografia do lado do servidor habilitada, o que pode expor dados sensíveis a acesso não autorizado."
	},
	"recommendation": {
		"en": "Enable server-side encryption by configuring server_side_encryption_rule with a valid sse_algorithm.",
		"zh": "通过配置 server_side_encryption_rule 和有效的 sse_algorithm 来开启服务端加密。",
		"ja": "SSEAlgorithm を KMS、AES256、または SM4 に設定して ServerSideEncryptionConfiguration プロパティを設定することで、OSS バケットのサーバー側暗号化を有効にします。",
		"de": "Aktivieren Sie die serverseitige Verschlüsselung für den OSS-Bucket, indem Sie die ServerSideEncryptionConfiguration-Eigenschaft mit SSEAlgorithm auf KMS, AES256 oder SM4 konfigurieren.",
		"es": "Habilite el cifrado del lado del servidor para el bucket OSS configurando la propiedad ServerSideEncryptionConfiguration con SSEAlgorithm establecido en KMS, AES256 o SM4.",
		"fr": "Activez le chiffrement côté serveur pour le bucket OSS en configurant la propriété ServerSideEncryptionConfiguration avec SSEAlgorithm défini sur KMS, AES256 ou SM4.",
		"pt": "Habilite criptografia do lado do servidor para o bucket OSS configurando a propriedade ServerSideEncryptionConfiguration com SSEAlgorithm definido como KMS, AES256 ou SM4."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

valid_algorithms := {"KMS", "AES256", "SM4"}

is_sse_enabled(resource) if {
	sse_rule := tf.get_attribute(resource, "server_side_encryption_rule", {})
	algorithm := object.get(sse_rule, "sse_algorithm", "")
	algorithm in valid_algorithms
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	not is_sse_enabled(resource)
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
