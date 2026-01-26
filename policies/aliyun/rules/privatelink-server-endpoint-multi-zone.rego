package infraguard.rules.aliyun.privatelink_server_endpoint_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "privatelink-server-endpoint-multi-zone",
	"name": {
		"en": "PrivateLink VPC Endpoint Service Multi-Zone Deployment",
		"zh": "PrivateLink 服务终端节点部署在多可用区",
	},
	"severity": "medium",
	"description": {
		"en": "PrivateLink VPC endpoint services should have resources deployed across multiple availability zones for high availability.",
		"zh": "PrivateLink 服务终端节点应将资源部署在多个可用区以实现高可用性。",
	},
	"reason": {
		"en": "The PrivateLink VPC endpoint service does not have resources in multiple zones, which may affect availability.",
		"zh": "PrivateLink 服务终端节点没有在多个可用区部署资源，可能影响可用性。",
	},
	"recommendation": {
		"en": "Deploy service resources across at least two availability zones by specifying multiple entries with different ZoneIds in the Resource property.",
		"zh": "通过在 Resource 属性中指定具有不同 ZoneId 的多个条目，将服务资源部署在至少两个可用区。",
	},
	"resource_types": ["ALIYUN::PrivateLink::VpcEndpointService"],
}

# Get unique zone IDs from resources
get_unique_zones(resource) := zones if {
	helpers.has_property(resource, "Resource")
	resources := resource.Properties.Resource
	zones := {r.ZoneId | some r in resources}
}

# Check if service has resources in multiple zones
has_multiple_zones(resource) if {
	zones := get_unique_zones(resource)
	count(zones) >= 2
}

# Deny rule: PrivateLink VPC endpoint services should have resources in multiple zones
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::PrivateLink::VpcEndpointService")
	not has_multiple_zones(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Resource"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
