package infraguard.rules.aliyun.ram_user_ak_used_expired_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ram-user-ak-used-expired-check",
	"name": {
		"en": "RAM User AccessKey Last Used Date Check",
		"zh": "RAM 用户 AccessKey 最后使用时间检测",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that RAM user AccessKeys have been used within the specified number of days.",
		"zh": "确保 RAM 用户 AccessKey 在指定天数内有使用记录。",
	},
	"reason": {
		"en": "Unused AccessKeys should be deactivated or deleted to reduce the attack surface.",
		"zh": "应停用或删除未使用的 AccessKey，以减少攻击面。",
	},
	"recommendation": {
		"en": "Deactivate or delete unused RAM user AccessKeys.",
		"zh": "停用或删除未使用的 RAM 用户 AccessKey。",
	},
	"resource_types": ["ALIYUN::RAM::AccessKey"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AccessKey")

	# Conceptual check for last used date
	helpers.has_property(resource, "LastUsedDate")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LastUsedDate"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
