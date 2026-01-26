package infraguard.rules.aliyun.ram_user_mfa_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ram-user-mfa-check",
	"name": {
		"en": "RAM User MFA Enabled",
		"zh": "RAM 用户开启 MFA",
	},
	"severity": "high",
	"description": {
		"en": "RAM users with console access should have multi-factor authentication (MFA) enabled.",
		"zh": "检测 RAM 用户是否开通 MFA 二次验证登录，开通视为合规。",
	},
	"reason": {
		"en": "RAM users without MFA are vulnerable to password compromise, posing a significant security risk.",
		"zh": "RAM 用户未开启 MFA，一旦密码泄露，账号将面临极大的安全风险。",
	},
	"recommendation": {
		"en": "Enable MFA for the RAM user by setting LoginProfile.MFABindRequired to true.",
		"zh": "通过将 LoginProfile.MFABindRequired 设置为 true 为 RAM 用户强制开启 MFA。",
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

# Check if MFA is required for login
is_mfa_enabled(resource) if {
	login_profile := helpers.get_property(resource, "LoginProfile", {})
	mfa := object.get(login_profile, "MFABindRequired", false)
	helpers.is_true(mfa)
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)

	# Only check users who have console access (LoginProfile exists)
	helpers.has_property(resource, "LoginProfile")
	not is_mfa_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LoginProfile", "MFABindRequired"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
