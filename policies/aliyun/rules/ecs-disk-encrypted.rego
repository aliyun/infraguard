package infraguard.rules.aliyun.ecs_disk_encrypted

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-disk-encrypted",
	"severity": "medium",
	"name": {
		"en": "ECS data disk encryption enabled",
		"zh": "ECS 数据磁盘开启加密",
		"ja": "ECS データディスクの暗号化が有効",
		"de": "ECS-Datendisk-Verschlüsselung aktiviert",
		"es": "Criptografía de disco de datos ECS habilitada",
		"fr": "Chiffrement du disque de données ECS activé",
		"pt": "Criptografia de disco de dados ECS habilitada"
	},
	"description": {
		"en": "ECS data disk has encryption enabled, considered compliant.",
		"zh": "ECS 数据磁盘已开启加密,视为合规。",
		"ja": "ECS データディスクで暗号化が有効になっている場合、準拠と見なされます。",
		"de": "ECS-Datendisk hat Verschlüsselung aktiviert, wird als konform betrachtet.",
		"es": "El disco de datos ECS tiene cifrado habilitado, se considera conforme.",
		"fr": "Le disque de données ECS a le chiffrement activé, considéré comme conforme.",
		"pt": "O disco de dados ECS tem criptografia habilitada, considerado conforme."
	},
	"reason": {
		"en": "ECS data disk does not have encryption enabled",
		"zh": "ECS 数据磁盘未开启加密",
		"ja": "ECS データディスクで暗号化が有効になっていません",
		"de": "ECS-Datendisk hat keine Verschlüsselung aktiviert",
		"es": "El disco de datos ECS no tiene cifrado habilitado",
		"fr": "Le disque de données ECS n'a pas le chiffrement activé",
		"pt": "O disco de dados ECS não tem criptografia habilitada"
	},
	"recommendation": {
		"en": "Enable encryption for ECS data disk to protect data at rest",
		"zh": "为 ECS 数据磁盘开启加密以保护静态数据",
		"ja": "保存データを保護するために、ECS データディスクで暗号化を有効にします",
		"de": "Aktivieren Sie die Verschlüsselung für ECS-Datendisks, um ruhende Daten zu schützen",
		"es": "Habilite el cifrado para el disco de datos ECS para proteger los datos en reposo",
		"fr": "Activez le chiffrement pour le disque de données ECS pour protéger les données au repos",
		"pt": "Habilite criptografia para disco de dados ECS para proteger dados em repouso"
	},
	"resource_types": ["ALIYUN::ECS::Disk"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")

	# Check if disk is encrypted
	encrypted := helpers.get_property(resource, "Encrypted", false)
	not helpers.is_true(encrypted)

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
