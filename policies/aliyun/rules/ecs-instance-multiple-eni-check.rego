package infraguard.rules.aliyun.ecs_instance_multiple_eni_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-instance-multiple-eni-check",
	"name": {
		"en": "ECS instance is bound to only one elastic network interface",
		"zh": "ECS 实例仅绑定一个弹性网卡",
	},
	"description": {
		"en": "ECS instances are bound to only one elastic network interface, considered compliant. This helps simplify network configuration and reduce complexity.",
		"zh": "ECS 实例仅绑定一个弹性网卡，视为合规。这有助于简化网络配置并减少复杂性。",
	},
	"severity": "low",
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
	"reason": {
		"en": "ECS instance is bound to multiple elastic network interfaces",
		"zh": "ECS 实例绑定了多个弹性网卡",
	},
	"recommendation": {
		"en": "Simplify instance network configuration by using only one ENI",
		"zh": "通过仅使用一个 ENI 来简化实例网络配置",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])

	# Check if NetworkInterfaces is specified with multiple ENIs
	network_interfaces := helpers.get_property(resource, "NetworkInterfaces", [])
	count(network_interfaces) > 1

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "NetworkInterfaces"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])

	# Count NetworkInterfaceAttachment resources that reference this instance
	attachment_count := count([att_name |
		some att_name, att_resource in helpers.resources_by_type("ALIYUN::ECS::NetworkInterfaceAttachment")
		instance_id := helpers.get_property(att_resource, "InstanceId", "")
		helpers.is_referencing(instance_id, name)
	])

	# If more than one attachment references this instance, it's a violation
	attachment_count > 1

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])

	# Count NetworkInterfaceAttachment resources that reference this instance via GetAtt
	attachment_count := count([att_name |
		some att_name, att_resource in helpers.resources_by_type("ALIYUN::ECS::NetworkInterfaceAttachment")
		instance_id := helpers.get_property(att_resource, "InstanceId", "")
		helpers.is_get_att_referencing(instance_id, name)
	])

	# If more than one attachment references this instance, it's a violation
	attachment_count > 1

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
