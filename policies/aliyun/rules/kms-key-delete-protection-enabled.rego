package infraguard.rules.aliyun.kms_key_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "kms-key-delete-protection-enabled",
	"name": {
		"en": "KMS key deletion protection enabled",
		"zh": "KMS 主密钥开启删除保护",
	},
	"description": {
		"en": "KMS master key has deletion protection enabled, considered compliant. Keys not in enabled status and service keys (which cannot be deleted) are not applicable.",
		"zh": "KMS 主密钥开启删除保护,视为合规。如果密钥状态非启用中,视为不适用,如果密钥为服务密钥,由于本身不可删除,视为不适用。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::KMS::Key"],
	"reason": {
		"en": "KMS key does not have deletion protection enabled",
		"zh": "KMS 主密钥未开启删除保护",
	},
	"recommendation": {
		"en": "Enable deletion protection for KMS key to prevent accidental deletion of critical encryption keys",
		"zh": "为 KMS 主密钥启用删除保护以防止意外删除关键加密密钥",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::KMS::Key")

	# Check if DeletionProtection is enabled
	deletion_protection := helpers.get_property(resource, "DeletionProtection", false)
	not helpers.is_true(deletion_protection)

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
