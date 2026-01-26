package infraguard.rules.aliyun.ecs_launch_template_network_type_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-launch-template-network-type-check",
	"name": {
		"en": "ECS launch template uses VPC network type",
		"zh": "ECS 启动模版配置不应设置公网访问",
	},
	"description": {
		"en": "ECS launch template versions have network type set to VPC, considered compliant. Classic network type is not recommended for production environments.",
		"zh": "ECS 启动模版版本中网络类型为 VPC 类型，视为合规。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::LaunchTemplate"],
	"reason": {
		"en": "ECS launch template is configured with classic network type",
		"zh": "ECS 启动模板配置了经典网络类型",
	},
	"recommendation": {
		"en": "Use VPC network type in launch templates for better network isolation",
		"zh": "在启动模板中使用 VPC 网络类型以获得更好的网络隔离",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::LaunchTemplate")

	# Check network type
	network_type := helpers.get_property(resource, "NetworkType", "")

	# Classic network is not recommended
	network_type == "classic"

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "NetworkType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
