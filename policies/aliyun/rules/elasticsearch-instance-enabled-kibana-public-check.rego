package infraguard.rules.aliyun.elasticsearch_instance_enabled_kibana_public_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "elasticsearch-instance-enabled-kibana-public-check",
	"name": {
		"en": "Elasticsearch Instance Kibana Does Not Enable Public Access",
		"zh": "Elasticsearch 实例 Kibana 未开启公网访问",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that Elasticsearch instance Kibana is not accessible from public networks.",
		"zh": "Elasticsearch 实例 Kibana 未开启公网访问，视为合规。",
	},
	"reason": {
		"en": "Elasticsearch instance Kibana is accessible from public network, which is a security risk.",
		"zh": "Elasticsearch 实例 Kibana 开启公网访问，存在安全风险。",
	},
	"recommendation": {
		"en": "Configure Kibana to only allow access from VPC or specific IPs.",
		"zh": "请配置 Kibana 仅允许 VPC 或特定 IP 访问。",
	},
	"resource_types": ["ALIYUN::ElasticSearch::Instance"],
}

# Check if Kibana public access is enabled
is_kibana_public_access_enabled(resource) if {
	resource.Properties.KibanaPublicNetworkAccess == true
}

is_kibana_public_access_enabled(resource) if {
	count(resource.Properties.KibanaWhitelist) > 0
	"0.0.0.0/0" in resource.Properties.KibanaWhitelist
}

is_kibana_public_access_enabled(resource) if {
	count(resource.Properties.KibanaWhitelist) > 0
	"0.0.0.0" in resource.Properties.KibanaWhitelist
}

is_kibana_public_access_enabled(resource) if {
	resource.Properties.KibanaWhitelist == "0.0.0.0/0"
}

is_kibana_public_access_enabled(resource) if {
	resource.Properties.KibanaWhitelist == "0.0.0.0"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ElasticSearch::Instance")
	is_kibana_public_access_enabled(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "KibanaPublicNetworkAccess"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
