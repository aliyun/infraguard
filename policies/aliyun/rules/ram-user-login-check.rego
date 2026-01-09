package infraguard.rules.aliyun.ram_user_login_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ram-user-login-check",
	"name": {
		"en": "RAM User Login Enabled Check",
		"zh": "RAM 用户登录启用检测",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that RAM users who do not need console access have login disabled.",
		"zh": "确保不需要控制台访问权限的 RAM 用户已禁用登录功能。",
	},
	"reason": {
		"en": "Disabling console login for users who only need API access reduces security risks.",
		"zh": "为仅需要 API 访问权限的用户禁用控制台登录可降低安全风险。",
	},
	"recommendation": {
		"en": "Disable console login for RAM users who only use AccessKeys.",
		"zh": "为仅使用 AccessKey 的 RAM 用户禁用控制台登录。",
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")
	helpers.get_property(resource, "LoginProfile", false)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LoginProfile"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
