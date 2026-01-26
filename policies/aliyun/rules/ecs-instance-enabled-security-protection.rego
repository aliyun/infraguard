package infraguard.rules.aliyun.ecs_instance_enabled_security_protection

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-instance-enabled-security-protection",
	"name": {
		"en": "ECS Instance Enabled Security Protection",
		"zh": "运行中的 ECS 实例开启云安全中心防护",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that ECS instances have security enhancement strategy enabled.",
		"zh": "确保 ECS 实例开启了安全增强策略（云安全中心防护）。",
	},
	"reason": {
		"en": "Without security protection, the instance is more vulnerable to attacks and malware.",
		"zh": "如果没有安全防护，实例更容易受到攻击和恶意软件的侵害。",
	},
	"recommendation": {
		"en": "Enable security enhancement strategy for the ECS instance by setting SecurityEnhancementStrategy to 'Active'.",
		"zh": "通过将 SecurityEnhancementStrategy 设置为 'Active' 为 ECS 实例开启安全增强策略。",
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

is_compliant(resource) if {
	helpers.get_property(resource, "SecurityEnhancementStrategy", "Active") == "Active"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityEnhancementStrategy"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
