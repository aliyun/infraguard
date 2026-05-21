package infraguard.rules.terraform.ecs_system_disk_size_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-system-disk-size-check",
	"severity": "low",
	"name": {
		"en": "ECS System Disk Size Check",
		"zh": "ECS 系统盘大小检查",
		"ja": "ECS システムディスクサイズチェック",
		"de": "ECS-Systemfestplatten-Größenprüfung",
		"es": "Verificación de Tamaño de Disco del Sistema ECS",
		"fr": "Vérification de la Taille du Disque Système ECS",
		"pt": "Verificação de Tamanho do Disco do Sistema ECS"
	},
	"description": {
		"en": "Ensures ECS system disks meet the minimum required size.",
		"zh": "确保 ECS 系统盘满足最低大小要求。",
		"ja": "ECS システムディスクが最小要件サイズを満たしていることを確認します。",
		"de": "Stellt sicher, dass ECS-Systemfestplatten die Mindestgrößenanforderung erfüllen.",
		"es": "Garantiza que los discos del sistema ECS cumplan con el tamaño mínimo requerido.",
		"fr": "Garantit que les disques système ECS répondent à la taille minimale requise.",
		"pt": "Garante que os discos do sistema ECS atendam ao tamanho mínimo necessário."
	},
	"reason": {
		"en": "System disks that are too small may run out of space, causing system instability.",
		"zh": "系统盘过小可能导致空间耗尽，引发系统不稳定。",
		"ja": "小さすぎるシステムディスクは容量不足になり、システムの不安定性を引き起こす可能性があります。",
		"de": "Zu kleine Systemfestplatten können keinen Speicherplatz mehr haben, was zu Systeminstabilität führt.",
		"es": "Los discos del sistema que son demasiado pequeños pueden quedarse sin espacio, causando inestabilidad del sistema.",
		"fr": "Les disques système trop petits peuvent manquer d'espace, provoquant une instabilité du système.",
		"pt": "Discos do sistema muito pequenos podem ficar sem espaço, causando instabilidade do sistema."
	},
	"recommendation": {
		"en": "Increase the system disk size to at least 40GB.",
		"zh": "将系统盘大小增加到至少 40GB。",
		"ja": "システムディスクサイズを少なくとも 40GB に増やします。",
		"de": "Erhöhen Sie die Systemfestplattengröße auf mindestens 40 GB.",
		"es": "Aumente el tamaño del disco del sistema a al menos 40 GB.",
		"fr": "Augmentez la taille du disque système à au moins 40 Go.",
		"pt": "Aumente o tamanho do disco do sistema para pelo menos 40 GB."
	},
	"resource_types": ["alicloud_instance"],
	"iac_type": "terraform"
}

violation_for(name) := {
	"id": rule_meta.id,
	"resource_id": sprintf("alicloud_instance.%s", [name]),
	"meta": {
		"severity": rule_meta.severity,
		"reason": rule_meta.reason,
		"recommendation": rule_meta.recommendation,
	},
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	size := tf.get_attribute(resource, "system_disk_size", 40)
	not tf.is_unknown(size)
	size < 40
	violation := violation_for(name)
}
