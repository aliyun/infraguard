package infraguard.rules.aliyun.ess_scaling_group_loadbalancer_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ess-scaling-group-loadbalancer-check",
	"name": {
		"en": "ESS Scaling Group Load Balancer Existence Check",
		"zh": "弹性伸缩组关联负载均衡存在性检测",
	},
	"severity": "medium",
	"description": {
		"en": "ESS scaling groups should be attached to existing and active Load Balancer instances for proper traffic distribution.",
		"zh": "弹性伸缩组关联传统型负载均衡或者应用负载均衡仍然为保有中资源，视为合规。",
	},
	"reason": {
		"en": "The ESS scaling group may be attached to a Load Balancer that no longer exists or is inactive.",
		"zh": "弹性伸缩组关联的负载均衡可能已不存在或已失效。",
	},
	"recommendation": {
		"en": "Ensure the Load Balancer IDs referenced in the scaling group are valid and active resources.",
		"zh": "确保伸缩组中引用的负载均衡 ID 是有效的保有中资源。",
	},
	"resource_types": ["ALIYUN::ESS::ScalingGroup"],
}

# Check if scaling group has load balancer IDs configured
has_load_balancer(resource) if {
	load_balancer_ids := helpers.get_property(resource, "LoadBalancerIds", [])
	count(load_balancer_ids) > 0
}

has_load_balancer(resource) if {
	server_groups := helpers.get_property(resource, "ServerGroups", [])
	count(server_groups) > 0
}

# Deny rule: ESS scaling groups should have valid load balancer attachments
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingGroup")
	not has_load_balancer(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LoadBalancerIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
