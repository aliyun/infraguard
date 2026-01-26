package infraguard.rules.aliyun.slb_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "slb-delete-protection-enabled",
	"name": {
		"en": "SLB Instance Deletion Protection Enabled",
		"zh": "SLB 实例开启释放保护",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that SLB instances have deletion protection enabled.",
		"zh": "确保 SLB 实例开启了释放保护。",
	},
	"reason": {
		"en": "If deletion protection is not enabled, the SLB instance may be released accidentally, causing service interruption.",
		"zh": "如果未开启释放保护，SLB 实例可能会被意外释放，导致业务中断。",
	},
	"recommendation": {
		"en": "Enable deletion protection for the SLB instance.",
		"zh": "为 SLB 实例开启释放保护功能。",
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
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
