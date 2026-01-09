package infraguard.rules.aliyun.ram_user_activated_ak_quantity_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:ram-user-activated-ak-quantity-check",
	"name": {
		"en": "RAM User Active AK Quantity Check",
		"zh": "RAM 用户激活 AccessKey 数量核查"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures RAM users do not have more than one active AccessKey.",
		"zh": "确保 RAM 用户激活的 AccessKey 数量不超过 1 个。"
	},
	"reason": {
		"en": "Limiting active AccessKeys reduces the potential impact of a credential leak.",
		"zh": "限制激活的 AccessKey 数量可降低凭据泄露的潜在危害。"
	},
	"recommendation": {
		"en": "Deactivate or remove unnecessary AccessKeys.",
		"zh": "禁用或移除不必要的 AccessKey。"
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

# Cross-resource check: Count ALIYUN::RAM::AccessKey referencing this user
count_active_aks(user_logical_id) := count([name |
	some name, res in helpers.resources_by_type("ALIYUN::RAM::AccessKey")
	helpers.matches_resource_id(helpers.get_property(res, "UserName", ""), user_logical_id, "UserName")
	# Assuming it's active by default or has a status property
])

deny contains result if {
	some user_logical_id, resource in helpers.resources_by_type("ALIYUN::RAM::User")
	count_active_aks(user_logical_id) > 1
	result := {
		"id": rule_meta.id,
		"resource_id": user_logical_id,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
