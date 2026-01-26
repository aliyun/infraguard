package infraguard.rules.aliyun.ecs_instance_ram_role_attached

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ecs-instance-ram-role-attached",
	"name": {
		"en": "ECS Instance RAM Role Attached",
		"zh": "ECS 实例被授予实例 RAM 角色",
	},
	"severity": "low",
	"description": {
		"en": "Ensures that ECS instances have an IAM role attached for secure access to other cloud services.",
		"zh": "确保 ECS 实例被授予了实例 RAM 角色，以便安全地访问其他云服务。",
	},
	"reason": {
		"en": "Using RAM roles instead of hardcoded AccessKeys improves security by providing temporary credentials.",
		"zh": "使用 RAM 角色代替硬编码的 AccessKey，通过提供临时凭证来提高安全性。",
	},
	"recommendation": {
		"en": "Attach a RAM role to the ECS instance.",
		"zh": "为 ECS 实例授予 RAM 角色。",
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

# Check if instance has RAM role attached
has_ram_role(resource) if {
	helpers.has_property(resource, "RamRoleName")
	role := resource.Properties.RamRoleName
	role != ""
}

# Deny rule: ECS instances should have RAM role attached
deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])
	not has_ram_role(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RamRoleName"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
