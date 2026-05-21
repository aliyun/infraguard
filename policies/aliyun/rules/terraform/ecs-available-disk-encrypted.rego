package infraguard.rules.terraform.ecs_available_disk_encrypted

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-available-disk-encrypted",
	"severity": "high",
	"name": {
		"en": "ECS Disk Encryption Enabled",
		"zh": "可用的磁盘均已加密",
		"ja": "ECS ディスク暗号化が有効",
		"de": "ECS-Festplattenverschlüsselung aktiviert",
		"es": "Cifrado de Disco ECS Habilitado",
		"fr": "Chiffrement de Disque ECS Activé",
		"pt": "Criptografia de Disco ECS Habilitada"
	},
	"description": {
		"en": "Ensures that all ECS disks are encrypted.",
		"zh": "确保所有 ECS 磁盘都已加密。",
		"ja": "すべての ECS ディスクが暗号化されていることを確認します。",
		"de": "Stellt sicher, dass alle ECS-Festplatten verschlüsselt sind.",
		"es": "Garantiza que todos los discos ECS estén cifrados.",
		"fr": "Garantit que tous les disques ECS sont chiffrés.",
		"pt": "Garante que todos os discos ECS estejam criptografados."
	},
	"reason": {
		"en": "Encryption protects data at rest from unauthorized physical access or theft.",
		"zh": "加密可以保护静态数据免受未经授权的物理访问或盗窃。",
		"ja": "暗号化により、保存データが不正な物理アクセスや盗難から保護されます。",
		"de": "Verschlüsselung schützt ruhende Daten vor unbefugtem physischem Zugriff oder Diebstahl.",
		"es": "El cifrado protege los datos en reposo del acceso físico no autorizado o el robo.",
		"fr": "Le chiffrement protège les données au repos contre l'accès physique non autorisé ou le vol.",
		"pt": "A criptografia protege dados em repouso contra acesso físico não autorizado ou roubo."
	},
	"recommendation": {
		"en": "Set encrypted to true for all ECS disks.",
		"zh": "将所有 ECS 磁盘的 encrypted 属性设置为 true。",
		"ja": "すべての ECS ディスクの 'Encrypted' を true に設定します。",
		"de": "Setzen Sie 'Encrypted' für alle ECS-Festplatten auf true.",
		"es": "Establezca 'Encrypted' en true para todos los discos ECS.",
		"fr": "Définissez 'Encrypted' sur true pour tous les disques ECS.",
		"pt": "Defina 'Encrypted' como true para todos os discos ECS."
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

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ecs_disk")
	not is_encrypted(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ecs_disk.%s", [name]),
		"violation_path": ["encrypted"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_disk")
	not is_encrypted(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_disk.%s", [name]),
		"violation_path": ["encrypted"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
