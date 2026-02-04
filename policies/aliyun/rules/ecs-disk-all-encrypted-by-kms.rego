package infraguard.rules.aliyun.ecs_disk_all_encrypted_by_kms

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-disk-all-encrypted-by-kms",
	"name": {
		"en": "ECS disk with KMS encryption enabled",
		"zh": "ECS 磁盘开启 KMS 加密",
		"ja": "KMS 暗号化が有効な ECS ディスク",
		"de": "ECS-Festplatte mit KMS-Verschlüsselung aktiviert",
		"es": "Disco ECS con Cifrado KMS Habilitado",
		"fr": "Disque ECS avec Chiffrement KMS Activé",
		"pt": "Disco ECS com Criptografia KMS Habilitada",
	},
	"description": {
		"en": "ECS disks (including system disk and data disks) are encrypted with KMS, considered compliant.",
		"zh": "ECS 磁盘(包括系统盘和数据盘)开启 KMS 加密，视为合规。",
		"ja": "ECS ディスク（システムディスクとデータディスクを含む）が KMS で暗号化されており、準拠と見なされます。",
		"de": "ECS-Festplatten (einschließlich Systemfestplatte und Datenträger) sind mit KMS verschlüsselt, was als konform gilt.",
		"es": "Los discos ECS (incluidos el disco del sistema y los discos de datos) están cifrados con KMS, considerado conforme.",
		"fr": "Les disques ECS (y compris le disque système et les disques de données) sont chiffrés avec KMS, considéré comme conforme.",
		"pt": "Os discos ECS (incluindo disco do sistema e discos de dados) estão criptografados com KMS, considerado conforme.",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::Disk"],
	"reason": {
		"en": "ECS disk is not encrypted with KMS",
		"zh": "ECS 磁盘未开启 KMS 加密",
		"ja": "ECS ディスクが KMS で暗号化されていない",
		"de": "ECS-Festplatte ist nicht mit KMS verschlüsselt",
		"es": "El disco ECS no está cifrado con KMS",
		"fr": "Le disque ECS n'est pas chiffré avec KMS",
		"pt": "O disco ECS não está criptografado com KMS",
	},
	"recommendation": {
		"en": "Enable KMS encryption for ECS disks by setting Encrypted to true and specifying a KMSKeyId",
		"zh": "通过设置 Encrypted 为 true 并指定 KMSKeyId 来为 ECS 磁盘启用 KMS 加密",
		"ja": "Encrypted を true に設定し、KMSKeyId を指定して ECS ディスクの KMS 暗号化を有効にします",
		"de": "Aktivieren Sie die KMS-Verschlüsselung für ECS-Festplatten, indem Sie Encrypted auf true setzen und eine KMSKeyId angeben",
		"es": "Habilite el cifrado KMS para discos ECS estableciendo Encrypted en true y especificando un KMSKeyId",
		"fr": "Activez le chiffrement KMS pour les disques ECS en définissant Encrypted sur true et en spécifiant un KMSKeyId",
		"pt": "Habilite a criptografia KMS para discos ECS definindo Encrypted como true e especificando um KMSKeyId",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")

	# Check if disk is encrypted
	encrypted := helpers.get_property(resource, "Encrypted", false)
	not helpers.is_true(encrypted)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Encrypted"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
