package infraguard.rules.aliyun.ecs_disk_idle_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ecs-disk-idle-check",
	"name": {
		"en": "ECS Disk Idle Check",
		"zh": "ECS 磁盘闲置检测",
	},
	"severity": "low",
	"description": {
		"en": "Ensures that ECS disks are attached to an instance and not in an idle state.",
		"zh": "确保 ECS 磁盘已挂载到实例，未处于闲置状态。",
	},
	"reason": {
		"en": "Idle disks still incur costs and may represent unused resources.",
		"zh": "闲置磁盘仍会产生费用，并且可能表示资源未被使用。",
	},
	"recommendation": {
		"en": "Attach the disk to an instance or delete it if it's no longer needed.",
		"zh": "将磁盘挂载到实例，如果不再需要，则将其删除。",
	},
	"resource_types": ["ALIYUN::ECS::Disk"],
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
