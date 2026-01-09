package infraguard.rules.aliyun.ecs_instance_deletion_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ecs-instance-deletion-protection-enabled",
	"name": {
		"en": "ECS Instance Deletion Protection Enabled",
		"zh": "ECS 实例开启释放保护",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that ECS instances have deletion protection enabled.",
		"zh": "确保 ECS 实例开启了释放保护。",
	},
	"reason": {
		"en": "If deletion protection is not enabled, the instance may be released accidentally, causing service interruption or data loss.",
		"zh": "如果未开启释放保护，实例可能会被意外释放，导致业务中断或数据丢失。",
	},
	"recommendation": {
		"en": "Enable deletion protection for the ECS instance.",
		"zh": "为 ECS 实例开启释放保护功能。",
	},
	"resource_types": ["ALIYUN::ECS::Instance"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeletionProtection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
