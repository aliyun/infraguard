package infraguard.rules.aliyun.root_has_specified_role

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:root-has-specified-role",
	"name": {
		"en": "Root Account Has Specified Role",
		"zh": "主账号具有指定的角色",
	},
	"severity": "low",
	"description": {
		"en": "Ensures that the root account has a specified RAM role for governance and management.",
		"zh": "确保主账号具有用于治理和管理的指定 RAM 角色。",
	},
	"reason": {
		"en": "Specific roles are required for cloud governance and management tools to function correctly.",
		"zh": "云治理和管理工具需要特定的角色才能正常运行。",
	},
	"recommendation": {
		"en": "Create and assign the specified RAM role to the root account.",
		"zh": "创建并为主账号分配指定的 RAM 角色。",
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")
	name == "root"
	not helpers.has_property(resource, "SpecifiedRole")
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
