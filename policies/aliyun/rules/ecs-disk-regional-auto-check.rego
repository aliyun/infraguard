package infraguard.rules.aliyun.ecs_disk_regional_auto_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ecs-disk-regional-auto-check",
	"name": {
		"en": "ECS Disk Zone-Redundant ESSD Storage",
		"zh": "使用同城冗余类型的 ESSD 数据盘",
	},
	"severity": "low",
	"description": {
		"en": "ECS data disks should use zone-redundant ESSD storage for high availability. System disks are not applicable to this rule.",
		"zh": "使用同城冗余类型的 ESSD 数据盘，视为合规。系统盘视为不适用。",
	},
	"reason": {
		"en": "The ECS data disk does not use zone-redundant storage, which may affect data availability.",
		"zh": "ECS 数据盘未使用同城冗余存储，可能影响数据可用性。",
	},
	"recommendation": {
		"en": "Use zone-redundant ESSD storage by setting DiskCategory to 'cloud_regional_disk_auto' or 'cloud_essd' with appropriate redundancy configuration.",
		"zh": "通过将 DiskCategory 设置为'cloud_regional_disk_auto'或配置适当冗余的'cloud_essd'来使用同城冗余 ESSD 存储。",
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
