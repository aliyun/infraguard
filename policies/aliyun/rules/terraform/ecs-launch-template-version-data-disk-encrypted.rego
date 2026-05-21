package infraguard.rules.terraform.ecs_launch_template_version_data_disk_encrypted

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-launch-template-version-data-disk-encrypted",
	"severity": "medium",
	"name": {
		"en": "ECS launch template version enables data disk encryption",
		"zh": "ECS 启动模版版本中设置数据磁盘加密",
		"ja": "ECS 起動テンプレートバージョンでデータディスク暗号化が有効",
		"de": "ECS-Startvorlagenversion aktiviert Datenfestplattenverschlüsselung",
		"es": "La Versión de Plantilla de Inicio ECS Habilita el Cifrado de Disco de Datos",
		"fr": "La Version du Modèle de Démarrage ECS Active le Chiffrement de Disque de Données",
		"pt": "A Versão do Modelo de Inicialização ECS Habilita a Criptografia de Disco de Dados"
	},
	"description": {
		"en": "All data disks configured in ECS launch template versions are encrypted, considered compliant.",
		"zh": "ECS 启动模版版本中数据磁盘配置均设置为加密，视为合规。",
		"ja": "ECS 起動テンプレートバージョンで設定されたすべてのデータディスクが暗号化されており、準拠と見なされます。",
		"de": "Alle in ECS-Startvorlagenversionen konfigurierten Datenfestplatten sind verschlüsselt und gelten als konform.",
		"es": "Todos los discos de datos configurados en las versiones de plantilla de inicio ECS están cifrados, considerado conforme.",
		"fr": "Tous les disques de données configurés dans les versions de modèle de démarrage ECS sont chiffrés, considéré comme conforme.",
		"pt": "Todos os discos de dados configurados nas versões do modelo de inicialização ECS estão criptografados, considerado conforme."
	},
	"reason": {
		"en": "ECS launch template version has data disks without encryption enabled",
		"zh": "ECS 启动模板版本的数据磁盘未启用加密",
		"ja": "ECS 起動テンプレートバージョンに暗号化が有効になっていないデータディスクがある",
		"de": "ECS-Startvorlagenversion hat Datenfestplatten ohne aktivierte Verschlüsselung",
		"es": "La versión de plantilla de inicio ECS tiene discos de datos sin cifrado habilitado",
		"fr": "La version du modèle de démarrage ECS a des disques de données sans chiffrement activé",
		"pt": "A versão do modelo de inicialização ECS tem discos de dados sem criptografia habilitada"
	},
	"recommendation": {
		"en": "Enable encryption for all data disks in launch template versions",
		"zh": "在启动模板版本中为所有数据磁盘启用加密",
		"ja": "起動テンプレートバージョンですべてのデータディスクの暗号化を有効にします",
		"de": "Aktivieren Sie die Verschlüsselung für alle Datenfestplatten in Startvorlagenversionen",
		"es": "Habilite el cifrado para todos los discos de datos en las versiones de plantilla de inicio",
		"fr": "Activez le chiffrement pour tous les disques de données dans les versions de modèle de démarrage",
		"pt": "Habilite a criptografia para todos os discos de dados nas versões do modelo de inicialização"
	},
	"resource_types": ["alicloud_ecs_launch_template", "alicloud_launch_template"],
	"iac_type": "terraform"
}

violation_for(resource_type, name) := {
	"id": rule_meta.id,
	"resource_id": sprintf("%s.%s", [resource_type, name]),
	"violation_path": ["data_disks", "encrypted"],
	"meta": {
		"severity": rule_meta.severity,
		"reason": rule_meta.reason,
		"recommendation": rule_meta.recommendation,
	},
}

disk_encrypted(disk) if {
	tf.get_attribute(disk, "encrypted", false) == true
}

disk_encrypted(disk) if {
	tf.get_attribute(disk, "encrypted", "") == "true"
}

has_unencrypted_data_disk(data_disks) if {
	is_array(data_disks)
	some disk in data_disks
	not disk_encrypted(disk)
}

has_unencrypted_data_disk(data_disks) if {
	is_object(data_disks)
	not disk_encrypted(data_disks)
}

deny contains violation if {
	some resource_type in rule_meta.resource_types
	some name, resource in tf.resources_by_type(resource_type)
	data_disks := tf.get_attribute(resource, "data_disks", [])
	not tf.is_unknown(data_disks)
	has_unencrypted_data_disk(data_disks)
	violation := violation_for(resource_type, name)
}
