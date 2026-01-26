package infraguard.rules.aliyun.dcdn_domain_multiple_origin_servers

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "dcdn-domain-multiple-origin-servers",
	"name": {
		"en": "DCDN Domain Multiple Origin Servers",
		"zh": "DCDN 域名配置多个源站",
	},
	"severity": "high",
	"description": {
		"en": "DCDN domains should be configured with multiple origin servers for high availability and fault tolerance.",
		"zh": "DCDN 域名配置多个源站，视为合规。",
	},
	"reason": {
		"en": "The DCDN domain is configured with only one origin server, creating a single point of failure.",
		"zh": "DCDN 域名仅配置了一个源站，存在单点故障风险。",
	},
	"recommendation": {
		"en": "Configure at least two origin servers in the Sources property to ensure high availability.",
		"zh": "在 Sources 属性中配置至少两个源站，以确保高可用性。",
	},
	"resource_types": ["ALIYUN::DCDN::Domain"],
}

# Check if domain has multiple origin servers
has_multiple_origin_servers(resource) if {
	sources := resource.Properties.Sources
	count(sources) >= 2
}

# Deny rule: DCDN domains must have multiple origin servers
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::DCDN::Domain")
	not has_multiple_origin_servers(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Sources"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
