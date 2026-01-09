package infraguard.rules.aliyun.mse_gateway_architecture_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:mse-gateway-architecture-check",
	"name": {
		"en": "MSE Gateway Has Multiple Nodes",
		"zh": "MSE 云原生网关多节点检测",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that MSE (Microservice Engine) gateways have more than 1 node for high availability.",
		"zh": "确保 MSE（微服务引擎）网关具有超过 1 个节点以实现高可用性。",
	},
	"reason": {
		"en": "Single-node gateways create a single point of failure and may cause service interruption.",
		"zh": "单节点网关存在单点故障，可能导致服务中断。",
	},
	"recommendation": {
		"en": "Configure the MSE gateway with at least 2 nodes.",
		"zh": "将 MSE 网关配置为至少 2 个节点。",
	},
	"resource_types": ["ALIYUN::MSE::Gateway"],
}

# Get node count from gateway
get_node_count(resource) := node_count if {
	# Use Replica property
	replica := helpers.get_property(resource, "Replica", 0)
	replica > 0
	node_count := replica
} else := node_count if {
	# Fall back to Nodes array
	nodes := helpers.get_property(resource, "Nodes", [])
	node_count := count(nodes)
}

# Check if gateway has more than 1 node
has_multi_nodes(resource) if {
	get_node_count(resource) > 1
}

is_compliant(resource) if {
	has_multi_nodes(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Gateway")
	not has_multi_nodes(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Replica"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
