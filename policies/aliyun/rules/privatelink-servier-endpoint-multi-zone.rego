package infraguard.rules.aliyun.privatelink_servier_endpoint_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "privatelink-servier-endpoint-multi-zone",
	"name": {
		"en": "PrivateLink Service Endpoint Multi-Zone Deployment",
		"zh": "PrivateLink 服务终端节点多可用区部署",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that PrivateLink service endpoints are deployed across multiple zones for high availability.",
		"zh": "确保 PrivateLink 服务终端节点部署在多个可用区以实现高可用性。",
	},
	"reason": {
		"en": "Multi-zone deployment ensures connectivity to the service even during an availability zone failure.",
		"zh": "多可用区部署可确保即使在可用区故障期间也能连接到服务。",
	},
	"recommendation": {
		"en": "Deploy PrivateLink service endpoints in at least two different availability zones.",
		"zh": "在至少两个不同的可用区中部署 PrivateLink 服务终端节点。",
	},
	"resource_types": ["ALIYUN::PrivateLink::VpcEndpoint"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::PrivateLink::VpcEndpoint")
	zones := helpers.get_property(resource, "Zone", [])
	count(zones) < 2
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Zone"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
