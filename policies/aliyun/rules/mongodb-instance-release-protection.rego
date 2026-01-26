package infraguard.rules.aliyun.mongodb_instance_release_protection

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mongodb-instance-release-protection",
	"name": {
		"en": "MongoDB Instance Release Protection Enabled",
		"zh": "MongoDB 实例开启释放保护",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that MongoDB instances have release protection enabled.",
		"zh": "确保 MongoDB 实例开启了释放保护。",
	},
	"reason": {
		"en": "If release protection is not enabled, the MongoDB instance may be released accidentally, causing data loss.",
		"zh": "如果未开启释放保护，MongoDB 实例可能会被意外释放，导致数据丢失。",
	},
	"recommendation": {
		"en": "Enable release protection for the MongoDB instance.",
		"zh": "为 MongoDB 实例开启释放保护功能。",
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DBInstanceReleaseProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MONGODB::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DBInstanceReleaseProtection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
