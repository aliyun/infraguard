package infraguard.rules.aliyun.oss_default_encryption_kms

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "oss-default-encryption-kms",
	"name": {
		"en": "OSS bucket server-side KMS encryption enabled",
		"zh": "OSS 存储空间开启服务端 KMS 加密",
		"ja": "OSS バケットのサーバー側 KMS 暗号化が有効",
		"de": "OSS-Bucket serverseitige KMS-Verschlüsselung aktiviert",
		"es": "Cifrado KMS del lado del servidor de bucket OSS habilitado",
		"fr": "Chiffrement KMS côté serveur de bucket OSS activé",
		"pt": "Criptografia KMS do lado do servidor de bucket OSS habilitada",
	},
	"description": {
		"en": "OSS bucket has server-side KMS encryption enabled, considered compliant.",
		"zh": "OSS 存储空间开启服务端 KMS 加密,视为合规。",
		"ja": "OSS バケットでサーバー側 KMS 暗号化が有効になっている場合、準拠と見なされます。",
		"de": "OSS-Bucket hat serverseitige KMS-Verschlüsselung aktiviert, wird als konform betrachtet.",
		"es": "El bucket OSS tiene cifrado KMS del lado del servidor habilitado, se considera conforme.",
		"fr": "Le bucket OSS a le chiffrement KMS côté serveur activé, considéré comme conforme.",
		"pt": "O bucket OSS tem criptografia KMS do lado do servidor habilitada, considerado conforme.",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::OSS::Bucket"],
	"reason": {
		"en": "OSS bucket does not have server-side KMS encryption enabled",
		"zh": "OSS 存储空间未开启服务端 KMS 加密",
		"ja": "OSS バケットでサーバー側 KMS 暗号化が有効になっていません",
		"de": "OSS-Bucket hat keine serverseitige KMS-Verschlüsselung aktiviert",
		"es": "El bucket OSS no tiene cifrado KMS del lado del servidor habilitado",
		"fr": "Le bucket OSS n'a pas le chiffrement KMS côté serveur activé",
		"pt": "O bucket OSS não tem criptografia KMS do lado do servidor habilitada",
	},
	"recommendation": {
		"en": "Enable server-side KMS encryption for OSS bucket to protect data at rest",
		"zh": "为 OSS 存储空间开启服务端 KMS 加密以保护静态数据",
		"ja": "保存データを保護するために、OSS バケットでサーバー側 KMS 暗号化を有効にします",
		"de": "Aktivieren Sie die serverseitige KMS-Verschlüsselung für OSS-Buckets, um ruhende Daten zu schützen",
		"es": "Habilite el cifrado KMS del lado del servidor para el bucket OSS para proteger los datos en reposo",
		"fr": "Activez le chiffrement KMS côté serveur pour le bucket OSS pour protéger les données au repos",
		"pt": "Habilite criptografia KMS do lado do servidor para bucket OSS para proteger dados em repouso",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")

	# Check if ServerSideEncryptionConfiguration is set with KMS
	sse_config := helpers.get_property(resource, "ServerSideEncryptionConfiguration", {})
	sse_algorithm := object.get(sse_config, "SSEAlgorithm", "")

	sse_algorithm != "KMS"

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
