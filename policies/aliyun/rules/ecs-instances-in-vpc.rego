package infraguard.rules.aliyun.ecs_instances_in_vpc

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-instances-in-vpc",
	"name": {
		"en": "ECS Instances in VPC",
		"zh": "使用专有网络类型的 ECS 实例",
	},
	"severity": "medium",
	"description": {
		"en": "ECS instances should be deployed in VPC (Virtual Private Cloud) networks rather than classic networks. VPC provides better network isolation, security, and flexibility.",
		"zh": "ECS 实例应部署在专有网络(VPC)而非经典网络中。VPC 提供更好的网络隔离、安全性和灵活性。",
	},
	"reason": {
		"en": "The ECS instance is not deployed in a VPC, which may result in insufficient network isolation and security.",
		"zh": "ECS 实例未部署在 VPC 中，可能导致网络隔离和安全性不足。",
	},
	"recommendation": {
		"en": "Deploy the ECS instance in a VPC by specifying the VpcId and VSwitchId properties.",
		"zh": "通过指定 VpcId 和 VSwitchId 属性，将 ECS 实例部署在 VPC 中。",
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

deny contains result if {
	some name, resource in helpers.resources_by_types({"ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"})
	not is_in_vpc(resource)
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

is_in_vpc(resource) if {
	helpers.has_property(resource, "VpcId")
	helpers.has_property(resource, "VSwitchId")
}
