package infraguard.rules.aliyun.ecs_instance_login_use_keypair

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ecs-instance-login-use-keypair",
	"name": {
		"en": "ECS Instance Login Using Key Pair",
		"zh": "ECS 实例登录使用密钥对",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that ECS instances use key pairs for login instead of passwords.",
		"zh": "确保 ECS 实例使用密钥对进行登录，而不是密码。",
	},
	"reason": {
		"en": "Key pair login is more secure than password login.",
		"zh": "密钥对登录比密码登录更安全。",
	},
	"recommendation": {
		"en": "Configure key pair login for the ECS instance and disable password login.",
		"zh": "为 ECS 实例配置密钥对登录，并禁用密码登录。",
	},
	"resource_types": ["ALIYUN::ECS::Instance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
	not helpers.has_property(resource, "KeyPairName")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "KeyPairName"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
