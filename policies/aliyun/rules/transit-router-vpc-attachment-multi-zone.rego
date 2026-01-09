package infraguard.rules.aliyun.transit_router_vpc_attachment_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:transit-router-vpc-attachment-multi-zone",
	"name": {
		"en": "Transit Router VPC Attachment Multi-Zone Configuration",
		"zh": "为转发路由器 VPC 连接设置多个可用区",
	},
	"severity": "high",
	"description": {
		"en": "Transit Router VPC attachments should be configured with vSwitches in at least two different availability zones for cross-zone high availability.",
		"zh": "为转发路由器的 VPC 连接设置两个分布在不同可用区的交换机，保障产品跨可用区的高可用性，视为合规。",
	},
	"reason": {
		"en": "The Transit Router VPC attachment is configured with vSwitches in only one availability zone, creating a single point of failure.",
		"zh": "转发路由器 VPC 连接仅配置了一个可用区的交换机，存在单点故障风险。",
	},
	"recommendation": {
		"en": "Configure at least two vSwitches in different availability zones in the ZoneMappings property.",
		"zh": "在 ZoneMappings 属性中配置至少两个不同可用区的交换机。",
	},
	"resource_types": ["ALIYUN::CEN::TransitRouterVpcAttachment"],
}

# Get unique zone IDs from zone mappings
unique_zones(zone_mappings) := zones if {
	zones := {zone_id |
		some mapping in zone_mappings
		zone_id := mapping.ZoneId
	}
}

# Check if attachment has multiple zones
has_multiple_zones(resource) if {
	zone_mappings := resource.Properties.ZoneMappings
	zones := unique_zones(zone_mappings)
	count(zones) >= 2
}

# Deny rule: Transit Router VPC attachments must have vSwitches in multiple zones
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CEN::TransitRouterVpcAttachment")
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
