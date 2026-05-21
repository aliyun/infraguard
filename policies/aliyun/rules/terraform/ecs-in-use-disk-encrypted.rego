package infraguard.rules.terraform.ecs_in_use_disk_encrypted

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-in-use-disk-encrypted",
	"severity": "medium",
	"name": {
		"en": "ECS In-Use Disk Encryption",
		"zh": "使用中的 ECS 数据磁盘开启加密",
		"ja": "ECS 使用中ディスクの暗号化",
		"de": "ECS-Disk-Verschlüsselung in Verwendung",
		"es": "Cifrado de Disco en Uso de ECS",
		"fr": "Chiffrement de Disque en Utilisation ECS",
		"pt": "Criptografia de Disco em Uso ECS"
	},
	"description": {
		"en": "ECS data disks should have encryption enabled to protect data at rest.",
		"zh": "使用中的 ECS 数据磁盘应开启加密以保护静态数据。",
		"ja": "ECS データディスクは、保存データを保護するために暗号化を有効にする必要があります。暗号化されたディスクは KMS キーを使用してデータを暗号化し、データのセキュリティと規制要件への準拠を確保します。",
		"de": "ECS-Datendisks sollten Verschlüsselung aktiviert haben, um ruhende Daten zu schützen. Verschlüsselte Disks verwenden KMS-Schlüssel zur Datenverschlüsselung und gewährleisten Datensicherheit und Compliance mit regulatorischen Anforderungen.",
		"es": "Los discos de datos ECS deben tener cifrado habilitado para proteger los datos en reposo. Los discos cifrados usan claves KMS para cifrar datos, asegurando la seguridad de los datos y el cumplimiento de los requisitos regulatorios.",
		"fr": "Les disques de données ECS doivent avoir le chiffrement activé pour protéger les données au repos. Les disques chiffrés utilisent des clés KMS pour chiffrer les données, garantissant la sécurité des données et la conformité aux exigences réglementaires.",
		"pt": "Discos de dados ECS devem ter criptografia habilitada para proteger dados em repouso. Discos criptografados usam chaves KMS para criptografar dados, garantindo segurança de dados e conformidade com requisitos regulatórios."
	},
	"reason": {
		"en": "The ECS disk does not have encryption enabled, which may expose sensitive data to unauthorized access.",
		"zh": "ECS 磁盘未开启加密，可能导致敏感数据暴露给未授权访问。",
		"ja": "ECS ディスクで暗号化が有効になっていないため、機密データが不正アクセスにさらされる可能性があります。",
		"de": "Die ECS-Disk hat keine Verschlüsselung aktiviert, was sensible Daten unbefugtem Zugriff aussetzen kann.",
		"es": "El disco ECS no tiene cifrado habilitado, lo que puede exponer datos sensibles a acceso no autorizado.",
		"fr": "Le disque ECS n'a pas le chiffrement activé, ce qui peut exposer des données sensibles à un accès non autorisé.",
		"pt": "O disco ECS não tem criptografia habilitada, o que pode expor dados sensíveis a acesso não autorizado."
	},
	"recommendation": {
		"en": "Enable encryption for the ECS disk by setting encrypted to true.",
		"zh": "通过将 encrypted 属性设置为 true 来为 ECS 磁盘启用加密。",
		"ja": "Encrypted プロパティを true に設定して、ECS ディスクの暗号化を有効にします。",
		"de": "Aktivieren Sie die Verschlüsselung für die ECS-Disk, indem Sie die Encrypted-Eigenschaft auf true setzen.",
		"es": "Habilite el cifrado para el disco ECS estableciendo la propiedad Encrypted en true.",
		"fr": "Activez le chiffrement pour le disque ECS en définissant la propriété Encrypted sur true.",
		"pt": "Habilite criptografia para o disco ECS definindo a propriedade Encrypted como true."
	},
	"resource_types": ["alicloud_disk", "alicloud_disk_attachment", "alicloud_ecs_disk", "alicloud_ecs_disk_attachment"],
	"iac_type": "terraform"
}

is_encrypted(resource) if {
	tf.get_attribute(resource, "encrypted", false) == true
}

is_encrypted(resource) if {
	tf.get_attribute(resource, "encrypted", "") == "true"
}

has_attachment(name) if {
	some _, attachment in tf.resources_by_type("alicloud_ecs_disk_attachment")
	disk_id := tf.get_attribute(attachment, "disk_id", "")
	tf.is_unknown(disk_id)
}

has_attachment(name) if {
	some _, attachment in tf.resources_by_type("alicloud_ecs_disk_attachment")
	disk_id := tf.get_attribute(attachment, "disk_id", "")
	not tf.is_unknown(disk_id)
	disk_id == name
}

has_attachment(name) if {
	some _, attachment in tf.resources_by_type("alicloud_disk_attachment")
	disk_id := tf.get_attribute(attachment, "disk_id", "")
	tf.is_unknown(disk_id)
}

has_attachment(name) if {
	some _, attachment in tf.resources_by_type("alicloud_disk_attachment")
	disk_id := tf.get_attribute(attachment, "disk_id", "")
	not tf.is_unknown(disk_id)
	disk_id == name
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ecs_disk")
	has_attachment(name)
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
	has_attachment(name)
	not is_encrypted(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_disk.%s", [name]),
		"violation_path": ["encrypted"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
