package infraguard.rules.aliyun.ram_user_group_membership_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ram-user-group-membership-check",
	"name": {
		"en": "RAM User Group Membership Check",
		"zh": "RAM 用户组归属检测",
	},
	"severity": "low",
	"description": {
		"en": "Ensures that RAM users belong to at least one group for easier permission management.",
		"zh": "确保 RAM 用户属于至少一个用户组，以便于权限管理。",
	},
	"reason": {
		"en": "Managing permissions through groups is more efficient and less error-prone than managing individual user permissions.",
		"zh": "通过组管理权限比管理单个用户的权限更高效且更不容易出错。",
	},
	"recommendation": {
		"en": "Assign RAM users to relevant user groups.",
		"zh": "将 RAM 用户分配到相关的用户组中。",
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	# Conceptual check for group membership
	not helpers.has_property(resource, "Groups")
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
