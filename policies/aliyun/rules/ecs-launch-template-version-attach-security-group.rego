package infraguard.rules.aliyun.ecs_launch_template_version_attach_security_group

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ecs-launch-template-version-attach-security-group",
	"name": {
		"en": "ECS launch template version attaches security groups",
		"zh": "ECS 启动模版版本中设置加入的安全组",
	},
	"description": {
		"en": "ECS launch template versions have security groups configured for instances, considered compliant.",
		"zh": "ECS 启动模版版本中设置了实例要加入的安全组，视为合规。",
	},
	"severity": "high",
	"resource_types": ["ALIYUN::ECS::LaunchTemplate"],
	"reason": {
		"en": "ECS launch template version does not have security groups configured",
		"zh": "ECS 启动模板版本未配置安全组",
	},
	"recommendation": {
		"en": "Configure security groups in launch template versions for instance network security",
		"zh": "在启动模板版本中配置安全组以确保实例网络安全",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::LaunchTemplate")

	# Check if security group is configured
	security_group_id := helpers.get_property(resource, "SecurityGroupId", "")
	security_group_ids := helpers.get_property(resource, "SecurityGroupIds", [])

	# Neither SecurityGroupId nor SecurityGroupIds is specified
	security_group_id == ""
	count(security_group_ids) == 0

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
