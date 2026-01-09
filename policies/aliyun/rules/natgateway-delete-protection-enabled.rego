package infraguard.rules.aliyun.natgateway_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:natgateway-delete-protection-enabled",
	"name": {
		"en": "NAT Gateway Deletion Protection Enabled",
		"zh": "NAT 网关启用释放保护",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that NAT Gateways have deletion protection enabled.",
		"zh": "确保 NAT 网关开启了释放保护。",
	},
	"reason": {
		"en": "If deletion protection is not enabled, the NAT Gateway may be released accidentally, causing loss of internet connectivity for resources in the VPC.",
		"zh": "如果未开启释放保护，NAT 网关可能会被意外释放，导致 VPC 内资源失去互联网连接。",
	},
	"recommendation": {
		"en": "Enable deletion protection for the NAT Gateway.",
		"zh": "为 NAT 网关开启释放保护功能。",
	},
	"resource_types": ["ALIYUN::VPC::NatGateway"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::NatGateway")
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
