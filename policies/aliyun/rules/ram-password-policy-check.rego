package infraguard.rules.aliyun.ram_password_policy_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ram-password-policy-check",
	"name": {
		"en": "RAM Password Policy Check",
		"zh": "RAM 密码策略检测",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the RAM password policy meets the specified security requirements.",
		"zh": "确保 RAM 密码策略符合指定的安全要求。",
	},
	"reason": {
		"en": "Strong password policies help prevent unauthorized access to accounts.",
		"zh": "强密码策略有助于防止对账号的未经授权访问。",
	},
	"recommendation": {
		"en": "Configure a strong RAM password policy including length, character types, and rotation.",
		"zh": "配置强 RAM 密码策略，包括长度、字符类型和定期轮换。",
	},
	"resource_types": ["ALIYUN::RAM::PasswordPolicy"],
}

# This rule typically checks RAM::PasswordPolicy resources
# Since a ROS template might not have this, we check it if it exists.
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::PasswordPolicy")

	# Logic to check properties like MinimumPasswordLength
	props := resource.Properties
	not props.MinimumPasswordLength >= 8
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "MinimumPasswordLength"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
