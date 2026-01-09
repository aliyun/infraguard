package infraguard.rules.aliyun.ess_scaling_group_attach_multi_switch

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ess-scaling-group-attach-multi-switch",
	"name": {
		"en": "ESS Scaling Group Multi-VSwitch",
		"zh": "弹性伸缩组关联至少两个交换机",
	},
	"severity": "medium",
	"description": {
		"en": "ESS scaling groups should be associated with at least two VSwitches for high availability across multiple zones.",
		"zh": "弹性伸缩组关联至少两个交换机，视为合规。",
	},
	"reason": {
		"en": "The ESS scaling group is associated with fewer than two VSwitches, which may affect availability.",
		"zh": "弹性伸缩组关联的交换机少于两个，可能影响可用性。",
	},
	"recommendation": {
		"en": "Configure at least two VSwitches in the VSwitchIds property to ensure high availability across multiple zones.",
		"zh": "在 VSwitchIds 属性中配置至少两个交换机，以确保跨多个可用区的高可用性。",
	},
	"resource_types": ["ALIYUN::ESS::ScalingGroup"],
}

# Check if scaling group has multiple VSwitches
has_multiple_vswitches(resource) if {
	vswitches := resource.Properties.VSwitchIds
	count(vswitches) >= 2
}

# Deny rule: ESS scaling groups must have at least two VSwitches
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingGroup")
	not has_multiple_vswitches(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VSwitchIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
