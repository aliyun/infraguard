package infraguard.rules.aliyun.redis_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:redis-instance-multi-zone",
	"name": {
		"en": "Redis Instance Multi-Zone Deployment",
		"zh": "Redis 实例多可用区部署",
	},
	"severity": "medium",
	"description": {
		"en": "Redis instances should be deployed across multiple availability zones for high availability.",
		"zh": "Redis 实例应部署在多个可用区。",
	},
	"reason": {
		"en": "The Redis instance is not configured with a secondary zone.",
		"zh": "Redis 实例未配置备用可用区。",
	},
	"recommendation": {
		"en": "Configure SecondaryZoneId to enable multi-zone deployment.",
		"zh": "配置 SecondaryZoneId 以启用多可用区部署。",
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

# Check if instance is multi-zone
is_multi_zone(resource) if {
	# Check if SecondaryZoneId is present and not empty
	object.get(resource.Properties, "SecondaryZoneId", "") != ""
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecondaryZoneId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
