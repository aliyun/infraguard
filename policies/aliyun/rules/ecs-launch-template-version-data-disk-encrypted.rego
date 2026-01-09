package infraguard.rules.aliyun.ecs_launch_template_version_data_disk_encrypted

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ecs-launch-template-version-data-disk-encrypted",
	"name": {
		"en": "ECS launch template version enables data disk encryption",
		"zh": "ECS 启动模版版本中设置数据磁盘加密",
	},
	"description": {
		"en": "All data disks configured in ECS launch template versions are encrypted, considered compliant.",
		"zh": "ECS 启动模版版本中数据磁盘配置均设置为加密，视为合规。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::LaunchTemplate"],
	"reason": {
		"en": "ECS launch template version has data disks without encryption enabled",
		"zh": "ECS 启动模板版本的数据磁盘未启用加密",
	},
	"recommendation": {
		"en": "Enable encryption for all data disks in launch template versions",
		"zh": "在启动模板版本中为所有数据磁盘启用加密",
	},
}

deny contains result if {
	some name, resource in input.Resources
	resource.Type == "ALIYUN::ECS::LaunchTemplate"
	resource.Properties.DiskMappings != null

	some disk in resource.Properties.DiskMappings
	disk.Encrypted != true

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DiskMappings", "Encrypted"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
