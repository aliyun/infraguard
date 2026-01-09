package infraguard.rules.aliyun.ecs_instance_chargetype_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:ecs-instance-chargetype-check",
	"name": {
		"en": "ECS Instance Charge Type Check",
		"zh": "ECS 实例付费类型核查"
	},
	"severity": "low",
	"description": {
		"en": "Ensures ECS instances use the authorized charge type.",
		"zh": "确保 ECS 实例使用授权的付费类型。"
	},
	"reason": {
		"en": "Enforcing specific charge types (e.g., PostPaid) aligns with organizational budget policies.",
		"zh": "强制执行特定的付费类型（如后付费）符合组织预算政策。"
	},
	"recommendation": {
		"en": "Set InstanceChargeType to 'PostPaid'.",
		"zh": "将 InstanceChargeType 设置为'PostPaid'。"
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

is_compliant(resource) if {
	charge_type := helpers.get_property(resource, "InstanceChargeType", "PostPaid")
	charge_type == "PostPaid"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "InstanceChargeType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
