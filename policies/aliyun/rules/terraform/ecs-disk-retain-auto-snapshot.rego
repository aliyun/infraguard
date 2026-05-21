package infraguard.rules.terraform.ecs_disk_retain_auto_snapshot

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-disk-retain-auto-snapshot",
	"severity": "medium",
	"name": {
		"en": "Retain auto snapshot when ECS disk is released",
		"zh": "ECS 数据磁盘释放时保留自动快照",
		"ja": "ECS ディスク解放時に自動スナップショットを保持",
		"de": "Automatische Momentaufnahme beibehalten, wenn ECS-Festplatte freigegeben wird",
		"es": "Retener Instantánea Automática cuando se Libera el Disco ECS",
		"fr": "Conserver l'Instantané Automatique lors de la Libération du Disque ECS",
		"pt": "Reter Instantâneo Automático quando o Disco ECS é Liberado"
	},
	"description": {
		"en": "Configure ECS disks to retain auto snapshots when released, considered compliant.",
		"zh": "设置 ECS 磁盘释放时保留自动快照，视为合规。",
		"ja": "ECS ディスクが解放されたときに自動スナップショットを保持するように設定し、準拠と見なされます。これは、誤削除からデータを保護するのに役立ちます。",
		"de": "Konfigurieren Sie ECS-Festplatten so, dass automatische Momentaufnahmen beim Freigeben beibehalten werden, was als konform gilt. Dies hilft, Daten vor versehentlichem Löschen zu schützen.",
		"es": "Configure los discos ECS para retener instantáneas automáticas cuando se liberen, considerado conforme. Esto ayuda a proteger los datos de eliminación accidental.",
		"fr": "Configurez les disques ECS pour conserver les instantanés automatiques lors de la libération, considéré comme conforme. Cela aide à protéger les données contre la suppression accidentelle.",
		"pt": "Configure os discos ECS para reter instantâneos automáticos quando liberados, considerado conforme. Isso ajuda a proteger os dados contra exclusão acidental."
	},
	"reason": {
		"en": "ECS disk will delete auto snapshots when released, risking data loss.",
		"zh": "ECS 磁盘释放时将删除自动快照，可能导致数据丢失。",
		"ja": "ECS ディスクは解放時に自動スナップショットを削除し、データ損失のリスクがあります",
		"de": "ECS-Festplatte löscht automatische Momentaufnahmen beim Freigeben, was Datenverlust riskiert",
		"es": "El disco ECS eliminará instantáneas automáticas cuando se libere, arriesgando pérdida de datos",
		"fr": "Le disque ECS supprimera les instantanés automatiques lors de la libération, risquant une perte de données",
		"pt": "O disco ECS excluirá instantâneos automáticos quando liberado, arriscando perda de dados"
	},
	"recommendation": {
		"en": "Set delete_auto_snapshot to false to retain auto snapshots when disk is released.",
		"zh": "将 delete_auto_snapshot 设置为 false 以在磁盘释放时保留自动快照。",
		"ja": "ディスクが解放されたときに自動スナップショットを保持するために、DeleteAutoSnapshot を false に設定します",
		"de": "Setzen Sie DeleteAutoSnapshot auf false, um automatische Momentaufnahmen beim Freigeben der Festplatte beizubehalten",
		"es": "Establezca DeleteAutoSnapshot en false para retener instantáneas automáticas cuando se libere el disco",
		"fr": "Définissez DeleteAutoSnapshot sur false pour conserver les instantanés automatiques lorsque le disque est libéré",
		"pt": "Defina DeleteAutoSnapshot como false para reter instantâneos automáticos quando o disco for liberado"
	},
	"resource_types": ["alicloud_disk", "alicloud_ecs_disk"],
	"iac_type": "terraform"
}

deletes_auto_snapshot(resource) if {
	tf.get_attribute(resource, "delete_auto_snapshot", false) == true
}

deletes_auto_snapshot(resource) if {
	tf.get_attribute(resource, "delete_auto_snapshot", "") == "true"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ecs_disk")
	deletes_auto_snapshot(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ecs_disk.%s", [name]),
		"violation_path": ["delete_auto_snapshot"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_disk")
	deletes_auto_snapshot(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_disk.%s", [name]),
		"violation_path": ["delete_auto_snapshot"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
