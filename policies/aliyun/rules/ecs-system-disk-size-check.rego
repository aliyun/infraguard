package infraguard.rules.aliyun.ecs_system_disk_size_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:ecs-system-disk-size-check",
	"name": {
		"en": "ECS System Disk Size Check",
		"zh": "ECS 系统盘大小检查"
	},
	"severity": "low",
	"description": {
		"en": "Ensures ECS system disks meet the minimum required size.",
		"zh": "确保 ECS 系统盘满足最低大小要求。"
	},
	"reason": {
		"en": "System disks that are too small may run out of space, causing system instability.",
		"zh": "系统盘过小可能导致空间耗尽，引发系统不稳定。"
	},
	"recommendation": {
		"en": "Increase the system disk size to at least 40GB.",
		"zh": "将系统盘大小增加到至少 40GB。"
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

is_compliant(resource) if {
	size := helpers.get_property(resource, "SystemDiskSize", 40)
	size >= 40
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SystemDiskSize"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
