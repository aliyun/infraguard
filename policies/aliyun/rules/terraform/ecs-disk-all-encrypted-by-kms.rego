package infraguard.rules.terraform.ecs_disk_all_encrypted_by_kms

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-disk-all-encrypted-by-kms",
	"severity": "medium",
	"name": {
		"en": "ECS disk with KMS encryption enabled",
		"zh": "ECS 磁盘开启 KMS 加密",
		"ja": "KMS 暗号化が有効な ECS ディスク",
		"de": "ECS-Festplatte mit KMS-Verschlüsselung aktiviert",
		"es": "Disco ECS con Cifrado KMS Habilitado",
		"fr": "Disque ECS avec Chiffrement KMS Activé",
		"pt": "Disco ECS com Criptografia KMS Habilitada"
	},
	"description": {
		"en": "ECS disks are encrypted with KMS, considered compliant.",
		"zh": "ECS 磁盘开启 KMS 加密，视为合规。",
		"ja": "ECS ディスク（システムディスクとデータディスクを含む）が KMS で暗号化されており、準拠と見なされます。",
		"de": "ECS-Festplatten (einschließlich Systemfestplatte und Datenträger) sind mit KMS verschlüsselt, was als konform gilt.",
		"es": "Los discos ECS (incluidos el disco del sistema y los discos de datos) están cifrados con KMS, considerado conforme.",
		"fr": "Les disques ECS (y compris le disque système et les disques de données) sont chiffrés avec KMS, considéré comme conforme.",
		"pt": "Os discos ECS (incluindo disco do sistema e discos de dados) estão criptografados com KMS, considerado conforme."
	},
	"reason": {
		"en": "ECS disk is not encrypted with KMS",
		"zh": "ECS 磁盘未开启 KMS 加密",
		"ja": "ECS ディスクが KMS で暗号化されていない",
		"de": "ECS-Festplatte ist nicht mit KMS verschlüsselt",
		"es": "El disco ECS no está cifrado con KMS",
		"fr": "Le disque ECS n'est pas chiffré avec KMS",
		"pt": "O disco ECS não está criptografado com KMS"
	},
	"recommendation": {
		"en": "Enable KMS encryption for ECS disks by setting encrypted to true and specifying kms_key_id.",
		"zh": "通过设置 encrypted 为 true 并指定 kms_key_id 来为 ECS 磁盘启用 KMS 加密。",
		"ja": "Encrypted を true に設定し、KMSKeyId を指定して ECS ディスクの KMS 暗号化を有効にします",
		"de": "Aktivieren Sie die KMS-Verschlüsselung für ECS-Festplatten, indem Sie Encrypted auf true setzen und eine KMSKeyId angeben",
		"es": "Habilite el cifrado KMS para discos ECS estableciendo Encrypted en true y especificando un KMSKeyId",
		"fr": "Activez le chiffrement KMS pour les disques ECS en définissant Encrypted sur true et en spécifiant un KMSKeyId",
		"pt": "Habilite a criptografia KMS para discos ECS definindo Encrypted como true e especificando um KMSKeyId"
	},
	"resource_types": ["alicloud_disk", "alicloud_ecs_disk"],
	"iac_type": "terraform"
}

is_encrypted(resource) if {
	tf.get_attribute(resource, "encrypted", false) == true
}

is_encrypted(resource) if {
	tf.get_attribute(resource, "encrypted", "") == "true"
}

has_kms_key(resource) if {
	kms_key_id := tf.get_attribute(resource, "kms_key_id", "")
	not tf.is_unknown(kms_key_id)
	kms_key_id != ""
}

is_kms_encrypted(resource) if {
	is_encrypted(resource)
	has_kms_key(resource)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ecs_disk")
	not is_kms_encrypted(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ecs_disk.%s", [name]),
		"violation_path": ["encrypted", "kms_key_id"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_disk")
	not is_kms_encrypted(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_disk.%s", [name]),
		"violation_path": ["encrypted", "kms_key_id"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
