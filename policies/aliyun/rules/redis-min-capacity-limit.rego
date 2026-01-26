package infraguard.rules.aliyun.redis_min_capacity_limit

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "redis-min-capacity-limit",
	"name": {
		"en": "Redis Min Capacity Limit",
		"zh": "Redis 实例满足指定内存容量要求"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Redis instance has memory capacity meeting the minimum requirement.",
		"zh": "确保 Redis 实例内存总量大于等于指定的参数值。"
	},
	"reason": {
		"en": "Adequate memory ensures Redis can handle the workload.",
		"zh": "充足的内存确保 Redis 能够处理工作负载。"
	},
	"recommendation": {
		"en": "Ensure Redis instance has minimum required memory capacity.",
		"zh": "确保 Redis 实例满足最低内存容量要求。"
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	capacity := helpers.get_property(resource, "Capacity", 1024)
	capacity >= 1024
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Capacity"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
