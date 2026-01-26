package infraguard.rules.aliyun.elasticsearch_instance_enabled_public_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "elasticsearch-instance-enabled-public-check",
	"name": {
		"en": "Elasticsearch Instance Does Not Enable Public Access",
		"zh": "Elasticsearch 实例未开启公网访问",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that Elasticsearch instances are not accessible from public networks.",
		"zh": "Elasticsearch 实例未开启公网访问，视为合规。",
	},
	"reason": {
		"en": "Elasticsearch instance is accessible from public network, which is a security risk.",
		"zh": "Elasticsearch 实例开启公网访问，存在安全风险。",
	},
	"recommendation": {
		"en": "Configure the instance to only allow access from VPC or specific IPs.",
		"zh": "请配置实例仅允许 VPC 或特定 IP 访问。",
	},
	"resource_types": ["ALIYUN::ElasticSearch::Instance"],
}

# Check if public network access is enabled
is_public_access_enabled(resource) if {
	resource.Properties.EnablePublic == true
}

is_public_access_enabled(resource) if {
	count(resource.Properties.PublicWhitelist) > 0
	"0.0.0.0/0" in resource.Properties.PublicWhitelist
}

is_public_access_enabled(resource) if {
	count(resource.Properties.PublicWhitelist) > 0
	"0.0.0.0" in resource.Properties.PublicWhitelist
}

is_public_access_enabled(resource) if {
	resource.Properties.PublicWhitelist == "0.0.0.0/0"
}

is_public_access_enabled(resource) if {
	resource.Properties.PublicWhitelist == "0.0.0.0"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ElasticSearch::Instance")
	is_public_access_enabled(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EnablePublic"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
