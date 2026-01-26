package infraguard.rules.aliyun.elasticsearch_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "elasticsearch-instance-multi-zone",
	"name": {
		"en": "Elasticsearch Instance Multi-Zone Deployment",
		"zh": "Elasticsearch 实例多可用区部署",
	},
	"severity": "medium",
	"description": {
		"en": "Elasticsearch instances should be deployed across multiple availability zones.",
		"zh": "Elasticsearch 实例应部署在多个可用区。",
	},
	"reason": {
		"en": "The Elasticsearch instance is configured with fewer than 2 availability zones.",
		"zh": "Elasticsearch 实例配置的可用区数量少于 2 个。",
	},
	"recommendation": {
		"en": "Increase the ZoneCount to at least 2.",
		"zh": "将 ZoneCount 增加到至少 2。",
	},
	"resource_types": ["ALIYUN::ElasticSearch::Instance"],
}

# Check if instance is multi-zone
is_multi_zone(resource) if {
	# Check ZoneCount >= 2
	object.get(resource.Properties, "ZoneCount", 1) >= 2
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ZoneCount"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
