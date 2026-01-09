package infraguard.rules.aliyun.mse_cluster_architecture_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:mse-cluster-architecture-check",
	"name": {
		"en": "MSE Cluster Has Multiple Nodes",
		"zh": "MSE 注册配置中心多节点检测",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that MSE (Microservice Engine) clusters have more than 3 nodes for high availability.",
		"zh": "确保 MSE（微服务引擎）集群具有超过 3 个节点以实现高可用性。",
	},
	"reason": {
		"en": "Clusters with 3 or fewer nodes may not provide adequate high availability.",
		"zh": "3 个或更少节点的集群可能无法提供足够的高可用性。",
	},
	"recommendation": {
		"en": "Configure the MSE cluster with more than 3 nodes.",
		"zh": "将 MSE 集群配置为超过 3 个节点。",
	},
	"resource_types": ["ALIYUN::MSE::Cluster"],
}

# Get node count from cluster
get_node_count(resource) := node_count if {
	# Try Nodes array first
	nodes := helpers.get_property(resource, "Nodes", [])
	count(nodes) > 0
	node_count := count(nodes)
} else := node_count if {
	# Fall back to InstanceCount
	instance_count := helpers.get_property(resource, "InstanceCount", 0)
	node_count := instance_count
}

# Check if cluster has more than 3 nodes
has_multi_nodes(resource) if {
	get_node_count(resource) > 3
}

is_compliant(resource) if {
	has_multi_nodes(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Cluster")
	not has_multi_nodes(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Nodes"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
