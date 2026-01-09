package infraguard.rules.aliyun.ess_scaling_group_attach_slb

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ess-scaling-group-attach-slb",
	"name": {
		"en": "ESS Scaling Group Attach SLB",
		"zh": "弹性伸缩组设置关联负载均衡",
	},
	"severity": "medium",
	"description": {
		"en": "ESS scaling groups should be attached to Classic Load Balancer (SLB) for proper traffic distribution.",
		"zh": "弹性伸缩组关联传统型负载均衡，视为合规。",
	},
	"reason": {
		"en": "The ESS scaling group is not attached to a Classic Load Balancer, which may affect traffic distribution.",
		"zh": "弹性伸缩组未关联传统型负载均衡，可能影响流量的分发和可用性。",
	},
	"recommendation": {
		"en": "Attach the scaling group to a Classic Load Balancer using the LoadBalancerIds property.",
		"zh": "使用 LoadBalancerIds 属性将伸缩组关联到传统型负载均衡实例。",
	},
	"resource_types": ["ALIYUN::ESS::ScalingGroup"],
}

# Check if scaling group has Classic Load Balancer attached
has_classic_slb(resource) if {
	load_balancer_ids := helpers.get_property(resource, "LoadBalancerIds", [])
	count(load_balancer_ids) > 0
}

# Deny rule: ESS scaling groups should be attached to Classic Load Balancer
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingGroup")
	not has_classic_slb(resource)
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
