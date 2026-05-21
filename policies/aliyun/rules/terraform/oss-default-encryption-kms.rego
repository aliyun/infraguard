package infraguard.rules.terraform.oss_default_encryption_kms

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-default-encryption-kms",
	"severity": "medium",
	"name": {
		"en": "OSS Bucket KMS Encryption Enabled",
		"zh": "OSS 存储空间开启服务端 KMS 加密",
		"ja": "OSS バケットのサーバー側 KMS 暗号化が有効",
		"de": "OSS-Bucket serverseitige KMS-Verschlüsselung aktiviert",
		"es": "Cifrado KMS del lado del servidor de bucket OSS habilitado",
		"fr": "Chiffrement KMS côté serveur de bucket OSS activé",
		"pt": "Criptografia KMS do lado do servidor de bucket OSS habilitada"
	},
	"description": {
		"en": "Ensures OSS bucket uses KMS for server-side encryption.",
		"zh": "确保 OSS 存储桶使用 KMS 进行服务端加密。",
		"ja": "OSS バケットでサーバー側 KMS 暗号化が有効になっている場合、準拠と見なされます。",
		"de": "OSS-Bucket hat serverseitige KMS-Verschlüsselung aktiviert, wird als konform betrachtet.",
		"es": "El bucket OSS tiene cifrado KMS del lado del servidor habilitado, se considera conforme.",
		"fr": "Le bucket OSS a le chiffrement KMS côté serveur activé, considéré comme conforme.",
		"pt": "O bucket OSS tem criptografia KMS do lado do servidor habilitada, considerado conforme."
	},
	"reason": {
		"en": "The OSS bucket does not use KMS for server-side encryption.",
		"zh": "OSS 存储桶未使用 KMS 进行服务端加密。",
		"ja": "OSS バケットでサーバー側 KMS 暗号化が有効になっていません",
		"de": "OSS-Bucket hat keine serverseitige KMS-Verschlüsselung aktiviert",
		"es": "El bucket OSS no tiene cifrado KMS del lado del servidor habilitado",
		"fr": "Le bucket OSS n'a pas le chiffrement KMS côté serveur activé",
		"pt": "O bucket OSS não tem criptografia KMS do lado do servidor habilitada"
	},
	"recommendation": {
		"en": "Set sse_algorithm to 'KMS' in server_side_encryption_rule.",
		"zh": "将 server_side_encryption_rule 中的 sse_algorithm 设置为 'KMS'。",
		"ja": "保存データを保護するために、OSS バケットでサーバー側 KMS 暗号化を有効にします",
		"de": "Aktivieren Sie die serverseitige KMS-Verschlüsselung für OSS-Buckets, um ruhende Daten zu schützen",
		"es": "Habilite el cifrado KMS del lado del servidor para el bucket OSS para proteger los datos en reposo",
		"fr": "Activez le chiffrement KMS côté serveur pour le bucket OSS pour protéger les données au repos",
		"pt": "Habilite criptografia KMS do lado do servidor para bucket OSS para proteger dados em repouso"
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

is_kms_encrypted(resource) if {
	sse_rule := tf.get_attribute(resource, "server_side_encryption_rule", {})
	algorithm := object.get(sse_rule, "sse_algorithm", "")
	algorithm == "KMS"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	not is_kms_encrypted(resource)
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
