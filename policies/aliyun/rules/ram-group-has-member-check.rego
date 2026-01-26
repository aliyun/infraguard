package infraguard.rules.aliyun.ram_group_has_member_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-group-has-member-check",
	"name": {
		"en": "RAM Group Has Member",
		"zh": "识别无成员的空 RAM 用户组"
	},
	"severity": "low",
	"description": {
		"en": "Ensures RAM groups have at least one member.",
		"zh": "确保 RAM 用户组至少包含一名成员。"
	},
	"reason": {
		"en": "Empty groups are often unused and should be removed to maintain a clean environment.",
		"zh": "空的用户组通常处于闲置状态，应予以移除以保持环境整洁。"
	},
	"recommendation": {
		"en": "Add members to the group or remove the empty group.",
		"zh": "向该组添加成员，或移除此空组。"
	},
	"resource_types": ["ALIYUN::RAM::Group"],
}

has_members(group_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::UserToGroupAddition")
	helpers.is_referencing(helpers.get_property(resource, "GroupName", ""), group_name)
}

deny contains result if {
	some group_name, resource in helpers.resources_by_type("ALIYUN::RAM::Group")

	# Check if this group is referenced in any UserToGroupAddition
	not has_members(group_name)
	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
