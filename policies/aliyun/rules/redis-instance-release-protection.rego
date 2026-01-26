package infraguard.rules.aliyun.redis_instance_release_protection

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "redis-instance-release-protection",
	"name": {
		"en": "Redis Instance Release Protection Enabled",
		"zh": "Redis 实例开启释放保护",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that Redis instances have release protection enabled.",
		"zh": "确保 Redis 实例开启了释放保护。",
	},
	"reason": {
		"en": "If release protection is not enabled, the Redis instance may be released accidentally, causing service interruption.",
		"zh": "如果未开启释放保护，Redis 实例可能会被意外释放，导致业务中断。",
	},
	"recommendation": {
		"en": "Enable release protection for the Redis instance.",
		"zh": "为 Redis 实例开启释放保护功能。",
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
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
