package infraguard.rules.aliyun.ecs_running_instances_in_vpc

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-running-instances-in-vpc",
	"name": {
		"en": "Running ECS instances are in VPC",
		"zh": "运行中的 ECS 实例在专有网络",
	},
	"description": {
		"en": "Running ECS instances are deployed in Virtual Private Cloud (VPC), considered compliant. This provides network isolation and enhanced security.",
		"zh": "阿里云推荐购买的 ECS 放在 VPC 里面。如果 ECS 有归属 VPC 则视为合规。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
	"reason": {
		"en": "ECS instance is not deployed in VPC (Classic network)",
		"zh": "ECS 实例未部署在专有网络（经典网络）",
	},
	"recommendation": {
		"en": "Deploy ECS instances in VPC for network isolation and enhanced security",
		"zh": "将 ECS 实例部署在专有网络中以实现网络隔离和增强安全性",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])

	# Check if instance is in classic network (no VPC specified)
	vpc_id := helpers.get_property(resource, "VpcId", "")
	vswitch_id := helpers.get_property(resource, "VSwitchId", "")

	# If neither VpcId nor VSwitchId is specified, it's classic network
	vpc_id == ""
	vswitch_id == ""

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
