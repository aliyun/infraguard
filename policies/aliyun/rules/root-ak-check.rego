package infraguard.rules.aliyun.root_ak_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:root-ak-check",
	"name": {
		"en": "Root User AccessKey Check",
		"zh": "主账号 AccessKey 检测",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that the root account does not have active AccessKeys.",
		"zh": "确保主账号没有激活的 AccessKey。",
	},
	"reason": {
		"en": "Using AccessKeys for the root account is a security risk. IAM roles or RAM user AccessKeys should be used instead.",
		"zh": "为主账号使用 AccessKey 存在安全风险。应改为使用 RAM 角色或 RAM 用户 AccessKey。",
	},
	"recommendation": {
		"en": "Delete any AccessKeys associated with the root account and use RAM users or roles.",
		"zh": "删除主账号的所有 AccessKey，并使用 RAM 用户或角色。",
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")
	name == "root"
	helpers.has_property(resource, "AccessKey") # Conceptual check
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AccessKey"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
