package infraguard.rules.aliyun.eip_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "eip-delete-protection-enabled",
	"name": {
		"en": "EIP Deletion Protection Enabled",
		"zh": "弹性公网 IP 开启删除保护",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that EIP instances have deletion protection enabled.",
		"zh": "确保弹性公网 IP 开启了删除保护。",
	},
	"reason": {
		"en": "If deletion protection is not enabled, the EIP may be released accidentally, potentially changing the public IP of your services.",
		"zh": "如果未开启删除保护，弹性公网 IP 可能会被意外释放，从而可能导致您的服务公网 IP 发生变化。",
	},
	"recommendation": {
		"en": "Enable deletion protection for the EIP instance.",
		"zh": "为弹性公网 IP 开启删除保护功能。",
	},
	"resource_types": ["ALIYUN::VPC::EIP"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::EIP")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeletionProtection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
