package infraguard.rules.aliyun.gwlb_loadbalancer_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:gwlb-loadbalancer-multi-zone",
	"name": {
		"en": "GWLB LoadBalancer Multi-Zone Deployment",
		"zh": "使用多可用区的网关型负载均衡实例",
	},
	"severity": "medium",
	"description": {
		"en": "GWLB LoadBalancer instances should be deployed across at least two availability zones for high availability.",
		"zh": "使用多可用区的网关型负载均衡实例，视为合规。",
	},
	"reason": {
		"en": "The GWLB LoadBalancer is deployed in fewer than two availability zones, creating a single point of failure risk.",
		"zh": "网关型负载均衡实例部署在少于两个可用区，存在单点故障风险。",
	},
	"recommendation": {
		"en": "Configure at least two zone mappings in the ZoneMappings property to ensure high availability.",
		"zh": "在 ZoneMappings 属性中配置至少两个可用区映射，以确保高可用性。",
	},
	"resource_types": ["ALIYUN::GWLB::LoadBalancer"],
}

# Check if LoadBalancer has multiple zones
has_multiple_zones(resource) if {
	zone_mappings := resource.Properties.ZoneMappings
	count(zone_mappings) >= 2
}

# Deny rule: GWLB LoadBalancers must be deployed in multiple zones
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::GWLB::LoadBalancer")
	not has_multiple_zones(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ZoneMappings"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
