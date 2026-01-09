package infraguard.rules.aliyun.alb_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:alb-delete-protection-enabled",
	"name": {
		"en": "ALB Instance Deletion Protection Enabled",
		"zh": "ALB 实例开启释放保护",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that ALB instances have deletion protection enabled.",
		"zh": "确保 ALB 实例开启了释放保护。",
	},
	"reason": {
		"en": "If deletion protection is not enabled, the ALB instance may be released accidentally, causing service interruption.",
		"zh": "如果未开启释放保护，ALB 实例可能会被意外释放，导致业务中断。",
	},
	"recommendation": {
		"en": "Enable deletion protection for the ALB instance.",
		"zh": "为 ALB 实例开启释放保护功能。",
	},
	"resource_types": ["ALIYUN::ALB::LoadBalancer"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtectionEnabled", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeletionProtectionEnabled"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
