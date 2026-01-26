package infraguard.rules.aliyun.ecs_instance_attached_security_group

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-instance-attached-security-group",
	"name": {
		"en": "ECS Instance Attached Security Group",
		"zh": "ECS 实例绑定安全组",
	},
	"severity": "high",
	"description": {
		"en": "If the ECS instance is included in the specified security group, the configuration is considered compliant.",
		"zh": "如果 ECS 实例已关联指定的安全组，则视为合规。",
	},
	"reason": {
		"en": "The ECS instance is not attached to any security group, which may leave it without proper network access control.",
		"zh": "ECS 实例未关联任何安全组，可能导致缺乏适当的网络访问控制。",
	},
	"recommendation": {
		"en": "Attach the ECS instance to at least one security group by setting SecurityGroupId or SecurityGroupIds property.",
		"zh": "通过设置 SecurityGroupId 或 SecurityGroupIds 属性，将 ECS 实例关联至少一个安全组。",
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

# Check if the instance has SecurityGroupId set
has_security_group_id(resource) if {
	helpers.has_property(resource, "SecurityGroupId")
	resource.Properties.SecurityGroupId != ""
}

# Check if the instance has SecurityGroupIds set with at least one entry
has_security_group_ids(resource) if {
	helpers.has_property(resource, "SecurityGroupIds")
	count(resource.Properties.SecurityGroupIds) > 0
}

# Instance is attached to security group if either property is set
is_attached_to_security_group(resource) if {
	has_security_group_id(resource)
}

is_attached_to_security_group(resource) if {
	has_security_group_ids(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_types({"ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"})
	not is_attached_to_security_group(resource)
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
