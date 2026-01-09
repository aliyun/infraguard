package infraguard.rules.aliyun.mongodb_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:mongodb-instance-multi-zone",
	"name": {
		"en": "MongoDB Instance Multi-Zone Deployment",
		"zh": "MongoDB 实例多可用区部署",
	},
	"severity": "medium",
	"description": {
		"en": "MongoDB instances should be deployed across multiple availability zones for high availability.",
		"zh": "MongoDB 实例应部署在多个可用区。",
	},
	"reason": {
		"en": "The MongoDB instance is not configured with a secondary or hidden zone.",
		"zh": "MongoDB 实例未配置备用可用区或隐藏可用区。",
	},
	"recommendation": {
		"en": "Configure SecondaryZoneId or HiddenZoneId to enable multi-zone deployment.",
		"zh": "配置 SecondaryZoneId 或 HiddenZoneId 以启用多可用区部署。",
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

# Check if instance is multi-zone
is_multi_zone(resource) if {
	# Check if SecondaryZoneId is present
	object.get(resource.Properties, "SecondaryZoneId", "") != ""
}

is_multi_zone(resource) if {
	# Check if HiddenZoneId is present
	object.get(resource.Properties, "HiddenZoneId", "") != ""
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
