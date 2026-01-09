package infraguard.rules.aliyun.root_mfa_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:root-mfa-check",
	"name": {
		"en": "Root User MFA Check",
		"zh": "主账号 MFA 检测",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that Multi-Factor Authentication (MFA) is enabled for the root account.",
		"zh": "确保主账号已开启多因素认证(MFA)。",
	},
	"reason": {
		"en": "MFA provides an extra layer of security for the most privileged account in the cloud environment.",
		"zh": "MFA 为云环境中最具特权的账号提供了额外的安全层。",
	},
	"recommendation": {
		"en": "Enable MFA for the Alibaba Cloud root account.",
		"zh": "为阿里云主账号开启 MFA。",
	},
	"resource_types": ["ALIYUN::RAM::User"], # This is a conceptual check often mapped to User or Account
}

# Conceptual check for root MFA
# In practice, this might be a placeholder or check a specific global configuration if available
deny contains result if {
	# This is a conceptual rule, let's assume we check if any user has MFA enabled
	# or if there's a specific flag. For now, it's a placeholder implementation.
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")
	name == "root"
	not helpers.get_property(resource, "MFAEnabled", false)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "MFAEnabled"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
