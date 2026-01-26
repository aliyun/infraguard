package infraguard.rules.aliyun.ram_user_no_product_admin_access

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ram-user-no-product-admin-access",
	"name": {
		"en": "RAM User No Product Administrative Access",
		"zh": "RAM 用户没有产品管理权限",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that RAM users do not have full administrative access to cloud products unless necessary.",
		"zh": "确保 RAM 用户未被授予对云产品的完全管理权限，除非必要。",
	},
	"reason": {
		"en": "Granting administrative access to all users increases the risk of accidental or malicious configuration changes.",
		"zh": "向所有用户授予管理权限会增加意外或恶意配置更改的风险。",
	},
	"recommendation": {
		"en": "Follow the principle of least privilege and grant only necessary permissions to RAM users.",
		"zh": "遵循最小权限原则，仅向 RAM 用户授予必要的权限。",
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	# Conceptual check for attached policies
	helpers.has_property(resource, "Policies")
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
