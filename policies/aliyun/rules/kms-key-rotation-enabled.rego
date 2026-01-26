package infraguard.rules.aliyun.kms_key_rotation_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "kms-key-rotation-enabled",
	"name": {
		"en": "KMS key automatic rotation enabled",
		"zh": "密钥管理服务设置主密钥自动轮转",
	},
	"description": {
		"en": "KMS user master key has automatic rotation enabled, considered compliant. Service keys and externally imported keys are not applicable.",
		"zh": "对密钥管理服务中的用户主密钥设置自动轮转,视为合规。如果是服务密钥,视为不适用。如果来源是用户自带密钥,视为不适用。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::KMS::Key"],
	"reason": {
		"en": "KMS key does not have automatic rotation enabled",
		"zh": "KMS 主密钥未开启自动轮转",
	},
	"recommendation": {
		"en": "Enable automatic rotation for KMS key to enhance security by regularly rotating encryption keys",
		"zh": "为 KMS 主密钥启用自动轮转以通过定期轮换加密密钥来增强安全性",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::KMS::Key")

	# Check if EnableAutomaticRotation is enabled
	rotation_enabled := helpers.get_property(resource, "EnableAutomaticRotation", false)
	not helpers.is_true(rotation_enabled)

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
