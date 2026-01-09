package infraguard.rules.aliyun.ecs_instance_not_bind_key_pair

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ecs-instance-not-bind-key-pair",
	"name": {
		"en": "ECS Instance Not Bound to Key Pair",
		"zh": "ECS 实例未绑定密钥对检测",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that ECS instances use key pairs for authentication instead of passwords.",
		"zh": "确保 ECS 实例使用密钥对进行身份验证，而不是密码。",
	},
	"reason": {
		"en": "Key pair authentication is more secure than password authentication.",
		"zh": "密钥对身份验证比密码身份验证更安全。",
	},
	"recommendation": {
		"en": "Bind a key pair to the ECS instance and disable password authentication.",
		"zh": "为 ECS 实例绑定密钥对，并禁用密码身份验证。",
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
