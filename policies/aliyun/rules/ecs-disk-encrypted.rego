package infraguard.rules.aliyun.ecs_disk_encrypted

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-disk-encrypted",
	"name": {
		"en": "ECS data disk encryption enabled",
		"zh": "ECS 数据磁盘开启加密",
	},
	"description": {
		"en": "ECS data disk has encryption enabled, considered compliant.",
		"zh": "ECS 数据磁盘已开启加密,视为合规。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::Disk"],
	"reason": {
		"en": "ECS data disk does not have encryption enabled",
		"zh": "ECS 数据磁盘未开启加密",
	},
	"recommendation": {
		"en": "Enable encryption for ECS data disk to protect data at rest",
		"zh": "为 ECS 数据磁盘开启加密以保护静态数据",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")

	# Check if disk is encrypted
	encrypted := helpers.get_property(resource, "Encrypted", false)
	not helpers.is_true(encrypted)

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
