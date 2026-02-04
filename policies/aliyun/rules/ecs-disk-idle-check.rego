package infraguard.rules.aliyun.ecs_disk_idle_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ecs-disk-idle-check",
	"severity": "low",
	"name": {
		"en": "ECS Disk Idle Check",
		"zh": "ECS 磁盘闲置检测",
		"ja": "ECS ディスクアイドルチェック",
		"de": "ECS-Disk-Leerlaufprüfung",
		"es": "Verificación de Disco Inactivo ECS",
		"fr": "Vérification de Disque Inactif ECS",
		"pt": "Verificação de Disco Inativo ECS"
	},
	"description": {
		"en": "Ensures that ECS disks are attached to an instance and not in an idle state.",
		"zh": "确保 ECS 磁盘已挂载到实例，未处于闲置状态。",
		"ja": "ECS ディスクがインスタンスに接続され、アイドル状態ではないことを確認します。",
		"de": "Stellt sicher, dass ECS-Disks an eine Instanz angehängt sind und nicht im Leerlaufzustand sind.",
		"es": "Garantiza que los discos ECS estén adjuntos a una instancia y no en estado inactivo.",
		"fr": "Garantit que les disques ECS sont attachés à une instance et ne sont pas dans un état inactif.",
		"pt": "Garante que os discos ECS estejam anexados a uma instância e não estejam em estado inativo."
	},
	"reason": {
		"en": "Idle disks still incur costs and may represent unused resources.",
		"zh": "闲置磁盘仍会产生费用，并且可能表示资源未被使用。",
		"ja": "アイドルディスクは依然としてコストがかかり、未使用のリソースを表している可能性があります。",
		"de": "Leerlaufende Disks verursachen weiterhin Kosten und können ungenutzte Ressourcen darstellen.",
		"es": "Los discos inactivos aún generan costos y pueden representar recursos no utilizados.",
		"fr": "Les disques inactifs génèrent toujours des coûts et peuvent représenter des ressources non utilisées.",
		"pt": "Discos inativos ainda geram custos e podem representar recursos não utilizados."
	},
	"recommendation": {
		"en": "Attach the disk to an instance or delete it if it's no longer needed.",
		"zh": "将磁盘挂载到实例，如果不再需要，则将其删除。",
		"ja": "ディスクをインスタンスに接続するか、不要になった場合は削除します。",
		"de": "Hängen Sie den Disk an eine Instanz an oder löschen Sie ihn, wenn er nicht mehr benötigt wird.",
		"es": "Adjunte el disco a una instancia o elimínelo si ya no es necesario.",
		"fr": "Attachez le disque à une instance ou supprimez-le s'il n'est plus nécessaire.",
		"pt": "Anexe o disco a uma instância ou exclua-o se não for mais necessário."
	},
	"resource_types": ["ALIYUN::ECS::Disk"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")

	# Conceptual check for attachment
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
