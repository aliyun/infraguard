package infraguard.rules.aliyun.kms_secret_rotation_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:kms-secret-rotation-enabled",
	"name": {
		"en": "KMS secret automatic rotation enabled",
		"zh": "密钥管理服务设置凭据自动轮转",
	},
	"description": {
		"en": "KMS secret has automatic rotation enabled, considered compliant. Generic secrets are not applicable.",
		"zh": "密钥管理服务中的凭据设置自动轮转,视为合规。如果密钥类型为普通密钥,视为不适用。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::KMS::Secret"],
	"reason": {
		"en": "KMS secret does not have automatic rotation enabled",
		"zh": "KMS 凭据未开启自动轮转",
	},
	"recommendation": {
		"en": "Enable automatic rotation for KMS secret to enhance security by regularly rotating credentials",
		"zh": "为 KMS 凭据启用自动轮转以通过定期轮换凭据来增强安全性",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::KMS::Secret")

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
