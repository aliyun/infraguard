package infraguard.rules.aliyun.ecs_disk_in_use

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-disk-in-use",
	"name": {
		"en": "ECS disk is in use",
		"zh": "ECS 磁盘正在使用中",
		"ja": "ECS ディスクが使用中",
		"de": "ECS-Festplatte ist in Verwendung",
		"es": "El Disco ECS Está en Uso",
		"fr": "Le Disque ECS est en Utilisation",
		"pt": "O Disco ECS Está em Uso",
	},
	"description": {
		"en": "ECS disks are attached to an instance or in use state, considered compliant. Disks that are available or unattached may be idle resources.",
		"zh": "ECS 磁盘已挂载到实例或处于使用中状态，视为合规。闲置或未挂载的磁盘可能造成资源浪费。",
		"ja": "ECS ディスクがインスタンスにアタッチされているか使用中状態であり、準拠と見なされます。利用可能またはアタッチされていないディスクはアイドルリソースである可能性があります。",
		"de": "ECS-Festplatten sind an eine Instanz angehängt oder im Gebrauchszustand, was als konform gilt. Verfügbare oder nicht angehängte Festplatten können inaktive Ressourcen sein.",
		"es": "Los discos ECS están adjuntos a una instancia o en estado de uso, considerado conforme. Los discos disponibles o no adjuntos pueden ser recursos inactivos.",
		"fr": "Les disques ECS sont attachés à une instance ou en état d'utilisation, considéré comme conforme. Les disques disponibles ou non attachés peuvent être des ressources inactives.",
		"pt": "Os discos ECS estão anexados a uma instância ou em estado de uso, considerado conforme. Discos disponíveis ou não anexados podem ser recursos ociosos.",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::Disk"],
	"reason": {
		"en": "ECS disk is not in use (Available status or unattached)",
		"zh": "ECS 磁盘未使用中（可用状态或未挂载）",
		"ja": "ECS ディスクが使用されていない（利用可能な状態またはアタッチされていない）",
		"de": "ECS-Festplatte ist nicht in Verwendung (Verfügbarer Status oder nicht angehängt)",
		"es": "El disco ECS no está en uso (estado disponible o no adjunto)",
		"fr": "Le disque ECS n'est pas en utilisation (statut disponible ou non attaché)",
		"pt": "O disco ECS não está em uso (status disponível ou não anexado)",
	},
	"recommendation": {
		"en": "Attach the disk to an ECS instance or release unused disks to save costs",
		"zh": "将磁盘挂载到 ECS 实例，或释放未使用的磁盘以节省成本",
		"ja": "ディスクを ECS インスタンスにアタッチするか、未使用のディスクを解放してコストを節約します",
		"de": "Hängen Sie die Festplatte an eine ECS-Instanz an oder geben Sie ungenutzte Festplatten frei, um Kosten zu sparen",
		"es": "Adjunte el disco a una instancia ECS o libere discos no utilizados para ahorrar costos",
		"fr": "Attachez le disque à une instance ECS ou libérez les disques non utilisés pour économiser des coûts",
		"pt": "Anexe o disco a uma instância ECS ou libere discos não utilizados para economizar custos",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")

	# Disk is not in use if not referenced by DiskAttachment and not attached via InstanceId
	not helpers.is_referenced_by_property(name, "ALIYUN::ECS::DiskAttachment", ["DiskId"])
	not helpers.has_property(resource, "InstanceId")

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
