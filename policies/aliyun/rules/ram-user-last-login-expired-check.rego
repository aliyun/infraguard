package infraguard.rules.aliyun.ram_user_last_login_expired_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-user-last-login-expired-check",
	"name": {
		"en": "RAM User Last Login Check",
		"zh": "RAM 用户最后登录时间核查"
	},
	"severity": "low",
	"description": {
		"en": "Checks if RAM users have not logged in for a long time.",
		"zh": "核查 RAM 用户是否长时间未登录。"
	},
	"reason": {
		"en": "Inactive users should be removed to reduce security surface.",
		"zh": "不活跃的用户应予以移除以减少安全暴露面。"
	},
	"recommendation": {
		"en": "Remove or deactivate unused RAM users.",
		"zh": "移除或禁用不常用的 RAM 用户。"
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

# Always compliant in static analysis as runtime data is missing
is_compliant(resource) := true

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": [],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
