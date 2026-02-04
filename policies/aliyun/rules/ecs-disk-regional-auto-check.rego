package infraguard.rules.aliyun.ecs_disk_regional_auto_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ecs-disk-regional-auto-check",
	"name": {
		"en": "ECS Disk Zone-Redundant ESSD Storage",
		"zh": "使用同城冗余类型的 ESSD 数据盘",
		"ja": "ECS ディスクゾーン冗長 ESSD ストレージ",
		"de": "ECS-Disk-Zonenredundanter ESSD-Speicher",
		"es": "Almacenamiento ESSD con Redundancia de Zona de Disco ECS",
		"fr": "Stockage ESSD Redondant par Zone de Disque ECS",
		"pt": "Armazenamento ESSD com Redundância de Zona de Disco ECS"
	},
	"severity": "low",
	"description": {
		"en": "ECS data disks should use zone-redundant ESSD storage for high availability. System disks are not applicable to this rule.",
		"zh": "使用同城冗余类型的 ESSD 数据盘，视为合规。系统盘视为不适用。",
		"ja": "ECS データディスクは高可用性のためにゾーン冗長 ESSD ストレージを使用する必要があります。システムディスクはこのルールには適用されません。",
		"de": "ECS-Datendisks sollten zonenredundanten ESSD-Speicher für hohe Verfügbarkeit verwenden. Systemdisks sind für diese Regel nicht anwendbar.",
		"es": "Los discos de datos ECS deben usar almacenamiento ESSD con redundancia de zona para alta disponibilidad. Los discos del sistema no son aplicables a esta regla.",
		"fr": "Les disques de données ECS doivent utiliser le stockage ESSD redondant par zone pour une haute disponibilité. Les disques système ne sont pas applicables à cette règle.",
		"pt": "Os discos de dados ECS devem usar armazenamento ESSD com redundância de zona para alta disponibilidade. Os discos do sistema não são aplicáveis a esta regra."
	},
	"reason": {
		"en": "The ECS data disk does not use zone-redundant storage, which may affect data availability.",
		"zh": "ECS 数据盘未使用同城冗余存储，可能影响数据可用性。",
		"ja": "ECS データディスクがゾーン冗長ストレージを使用していないため、データの可用性に影響を与える可能性があります。",
		"de": "Der ECS-Datendisk verwendet keinen zonenredundanten Speicher, was die Datenverfügbarkeit beeinträchtigen kann.",
		"es": "El disco de datos ECS no usa almacenamiento con redundancia de zona, lo que puede afectar la disponibilidad de datos.",
		"fr": "Le disque de données ECS n'utilise pas de stockage redondant par zone, ce qui peut affecter la disponibilité des données.",
		"pt": "O disco de dados ECS não usa armazenamento com redundância de zona, o que pode afetar a disponibilidade dos dados."
	},
	"recommendation": {
		"en": "Use zone-redundant ESSD storage by setting DiskCategory to 'cloud_regional_disk_auto' or 'cloud_essd' with appropriate redundancy configuration.",
		"zh": "通过将 DiskCategory 设置为'cloud_regional_disk_auto'或配置适当冗余的'cloud_essd'来使用同城冗余 ESSD 存储。",
		"ja": "DiskCategory を 'cloud_regional_disk_auto' に設定するか、適切な冗長性設定で 'cloud_essd' を使用して、ゾーン冗長 ESSD ストレージを使用します。",
		"de": "Verwenden Sie zonenredundanten ESSD-Speicher, indem Sie DiskCategory auf 'cloud_regional_disk_auto' setzen oder 'cloud_essd' mit entsprechender Redundanzkonfiguration verwenden.",
		"es": "Use almacenamiento ESSD con redundancia de zona estableciendo DiskCategory en 'cloud_regional_disk_auto' o 'cloud_essd' con configuración de redundancia apropiada.",
		"fr": "Utilisez le stockage ESSD redondant par zone en définissant DiskCategory sur 'cloud_regional_disk_auto' ou 'cloud_essd' avec une configuration de redondance appropriée.",
		"pt": "Use armazenamento ESSD com redundância de zona definindo DiskCategory como 'cloud_regional_disk_auto' ou 'cloud_essd' com configuração de redundância apropriada."
	},
	"resource_types": ["ALIYUN::ECS::Disk"],
}

# Check if disk is zone-redundant
is_zone_redundant(resource) if {
	disk_category := resource.Properties.DiskCategory
	disk_category == "cloud_regional_disk_auto"
}

# Check if disk is attached to an instance (system disks are created with instance)
is_data_disk(resource) if {
	# Data disks don't have InstanceId set (they are created separately)
	not helpers.has_property(resource, "InstanceId")
}

# Deny rule: ECS data disks should use zone-redundant storage
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")

	# Only check data disks
	is_data_disk(resource)

	# Check if not zone-redundant
	not is_zone_redundant(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DiskCategory"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
