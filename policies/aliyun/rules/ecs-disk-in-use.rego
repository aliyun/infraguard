package infraguard.rules.aliyun.ecs_disk_in_use

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-disk-in-use",
	"name": {
		"en": "ECS disk is in use",
		"zh": "ECS 磁盘正在使用中",
	},
	"description": {
		"en": "ECS disks are attached to an instance or in use state, considered compliant. Disks that are available or unattached may be idle resources.",
		"zh": "ECS 磁盘已挂载到实例或处于使用中状态，视为合规。闲置或未挂载的磁盘可能造成资源浪费。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::Disk"],
	"reason": {
		"en": "ECS disk is not in use (Available status or unattached)",
		"zh": "ECS 磁盘未使用中（可用状态或未挂载）",
	},
	"recommendation": {
		"en": "Attach the disk to an ECS instance or release unused disks to save costs",
		"zh": "将磁盘挂载到 ECS 实例，或释放未使用的磁盘以节省成本",
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
