package infraguard.rules.aliyun.rds_instacne_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:rds-instacne-delete-protection-enabled",
	"name": {
		"en": "RDS Instance Deletion Protection Enabled",
		"zh": "RDS 实例开启删除保护",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that RDS instances have deletion protection enabled.",
		"zh": "确保 RDS 实例开启了删除保护。",
	},
	"reason": {
		"en": "If deletion protection is not enabled, the RDS instance may be released accidentally, causing data loss.",
		"zh": "如果未开启删除保护，RDS 实例可能会被意外释放，导致数据丢失。",
	},
	"recommendation": {
		"en": "Enable deletion protection for the RDS instance.",
		"zh": "为 RDS 实例开启删除保护功能。",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
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
