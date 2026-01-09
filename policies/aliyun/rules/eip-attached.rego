package infraguard.rules.aliyun.eip_attached

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:eip-attached",
	"name": {
		"en": "EIP Attached",
		"zh": "EIP 必须处于绑定状态"
	},
	"severity": "low",
	"description": {
		"en": "Ensures that EIP instances are associated with a resource.",
		"zh": "确保 EIP 实例已与资源关联。"
	},
	"reason": {
		"en": "Unattached EIPs incur costs without providing any service.",
		"zh": "未绑定的 EIP 会产生费用，但未提供任何服务。"
	},
	"recommendation": {
		"en": "Associate the EIP with an ECS instance, NAT Gateway, or Load Balancer.",
		"zh": "将 EIP 与 ECS 实例、NAT 网关或负载均衡器关联。"
	},
	"resource_types": ["ALIYUN::VPC::EIP"],
}

# In ROS, attachment is usually done via ALIYUN::VPC::EIPAssociation
is_attached(eip_id) if {
	some name, res in helpers.resources_by_type("ALIYUN::VPC::EIPAssociation")
	helpers.is_referencing(helpers.get_property(res, "AllocationId", ""), eip_id)
}

deny contains result if {
	some eip_id, resource in helpers.resources_by_type("ALIYUN::VPC::EIP")
	not is_attached(eip_id)
	result := {
		"id": rule_meta.id,
		"resource_id": eip_id,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
