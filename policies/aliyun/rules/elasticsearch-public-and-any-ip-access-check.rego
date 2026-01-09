package infraguard.rules.aliyun.elasticsearch_public_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:elasticsearch-public-and-any-ip-access-check",
	"name": {
		"en": "Elasticsearch Public and Any IP Access Check",
		"zh": "Elasticsearch 实例未开启公网或不允许任意 IP 访问",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that Elasticsearch instances do not have public access enabled or an open whitelist.",
		"zh": "确保 Elasticsearch 实例未开启公网访问，或者白名单未设置为对所有 IP 开放。",
	},
	"reason": {
		"en": "Public access or an open whitelist exposes the Elasticsearch cluster to the internet, increasing the risk of unauthorized access or attacks.",
		"zh": "开启公网访问或设置开放白名单会将 Elasticsearch 集群暴露在互联网上，增加未经授权访问或攻击的风险。",
	},
	"recommendation": {
		"en": "Disable public access or restrict the IP whitelist for the Elasticsearch instance.",
		"zh": "禁用 Elasticsearch 实例的公网访问或限制 IP 白名单。",
	},
	"resource_types": ["ALIYUN::ElasticSearch::Instance"],
}

is_compliant(resource) if {
	# If public access is not enabled, it's compliant
	not helpers.is_true(helpers.get_property(resource, "EnablePublic", false))
}

is_compliant(resource) if {
	# If public access is enabled, check the whitelist
	helpers.is_true(helpers.get_property(resource, "EnablePublic", false))
	whitelist := helpers.get_property(resource, "PublicWhitelist", [])
	not has_open_cidr(whitelist)
}

has_open_cidr(whitelist) if {
	some cidr in whitelist
	helpers.is_public_cidr(cidr)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ElasticSearch::Instance")
	not is_compliant(resource)
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
