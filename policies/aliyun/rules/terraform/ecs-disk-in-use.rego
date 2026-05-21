package infraguard.rules.terraform.ecs_disk_in_use

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-disk-in-use",
	"severity": "medium",
	"name": {
		"en": "ECS disk is in use",
		"zh": "ECS 磁盘正在使用中",
		"ja": "ECS ディスクが使用中",
		"de": "ECS-Festplatte ist in Verwendung",
		"es": "El Disco ECS Está en Uso",
		"fr": "Le Disque ECS est en Utilisation",
		"pt": "O Disco ECS Está em Uso"
	},
	"description": {
		"en": "ECS disks are attached to an instance or in use state, considered compliant.",
		"zh": "ECS 磁盘已挂载到实例或处于使用中状态，视为合规。",
		"ja": "ECS ディスクがインスタンスにアタッチされているか使用中状態であり、準拠と見なされます。利用可能またはアタッチされていないディスクはアイドルリソースである可能性があります。",
		"de": "ECS-Festplatten sind an eine Instanz angehängt oder im Gebrauchszustand, was als konform gilt. Verfügbare oder nicht angehängte Festplatten können inaktive Ressourcen sein.",
		"es": "Los discos ECS están adjuntos a una instancia o en estado de uso, considerado conforme. Los discos disponibles o no adjuntos pueden ser recursos inactivos.",
		"fr": "Les disques ECS sont attachés à une instance ou en état d'utilisation, considéré comme conforme. Les disques disponibles ou non attachés peuvent être des ressources inactives.",
		"pt": "Os discos ECS estão anexados a uma instância ou em estado de uso, considerado conforme. Discos disponíveis ou não anexados podem ser recursos ociosos."
	},
	"reason": {
		"en": "ECS disk is not in use or is unattached.",
		"zh": "ECS 磁盘未使用中或未挂载。",
		"ja": "ECS ディスクが使用されていない（利用可能な状態またはアタッチされていない）",
		"de": "ECS-Festplatte ist nicht in Verwendung (Verfügbarer Status oder nicht angehängt)",
		"es": "El disco ECS no está en uso (estado disponible o no adjunto)",
		"fr": "Le disque ECS n'est pas en utilisation (statut disponible ou non attaché)",
		"pt": "O disco ECS não está em uso (status disponível ou não anexado)"
	},
	"recommendation": {
		"en": "Attach the disk to an ECS instance or release unused disks to save costs.",
		"zh": "将磁盘挂载到 ECS 实例，或释放未使用的磁盘以节省成本。",
		"ja": "ディスクを ECS インスタンスにアタッチするか、未使用のディスクを解放してコストを節約します",
		"de": "Hängen Sie die Festplatte an eine ECS-Instanz an oder geben Sie ungenutzte Festplatten frei, um Kosten zu sparen",
		"es": "Adjunte el disco a una instancia ECS o libere discos no utilizados para ahorrar costos",
		"fr": "Attachez le disque à une instance ECS ou libérez les disques non utilisés pour économiser des coûts",
		"pt": "Anexe o disco a uma instância ECS ou libere discos não utilizados para economizar custos"
	},
	"resource_types": ["alicloud_disk", "alicloud_disk_attachment", "alicloud_ecs_disk", "alicloud_ecs_disk_attachment"],
	"iac_type": "terraform"
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
	not has_attachment(name)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ecs_disk.%s", [name]),
		"violation_path": ["alicloud_ecs_disk_attachment"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_disk")
	not has_attachment(name)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_disk.%s", [name]),
		"violation_path": ["alicloud_disk_attachment"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
