package infraguard.rules.aliyun.acs_cluster_node_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "acs-cluster-node-multi-zone",
	"name": {
		"en": "ACS Cluster Node Multi-Zone Deployment",
		"zh": "使用区域级多可用区 ACS 集群",
	},
	"severity": "high",
	"description": {
		"en": "The ACS cluster nodes should be distributed across 3 or more availability zones for high availability.",
		"zh": "使用区域级 ACS 集群，节点分布在 3 个及以上可用区，视为合规。",
	},
	"reason": {
		"en": "The ACS cluster nodes are not distributed across 3 or more availability zones.",
		"zh": "ACS 集群节点未分布在 3 个及以上可用区。",
	},
	"recommendation": {
		"en": "Configure the cluster to use at least 3 availability zones by specifying multiple ZoneIds or VSwitchIds.",
		"zh": "通过指定多个 ZoneIds 或 VSwitchIds，将集群配置为使用至少 3 个可用区。",
	},
	"resource_types": ["ALIYUN::ACS::Cluster"],
}

# Check if cluster is multi-zone
is_multi_zone(resource) if {
	count(object.get(resource.Properties, "ZoneIds", [])) >= 3
}

is_multi_zone(resource) if {
	# If ZoneIds is not provided, check VSwitchIds as a proxy if ZoneIds is missing
	not object.get(resource.Properties, "ZoneIds", [])
	count(object.get(resource.Properties, "VSwitchIds", [])) >= 3
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ZoneIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
