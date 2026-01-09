package infraguard.rules.aliyun.ess_scaling_configuration_attach_security_group

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ess-scaling-configuration-attach-security-group",
	"name": {
		"en": "ESS Scaling Configuration Security Group",
		"zh": "弹性伸缩配置中为实例设置关联安全组",
	},
	"severity": "medium",
	"description": {
		"en": "ESS scaling configurations should attach security groups to instances for proper network isolation and access control.",
		"zh": "弹性伸缩配置中设置了实例要加入的安全组，视为合规。",
	},
	"reason": {
		"en": "The ESS scaling configuration does not have security groups attached, which may result in instances without proper network access control.",
		"zh": "弹性伸缩配置未关联安全组，实例可能缺少网络访问控制。",
	},
	"recommendation": {
		"en": "Add security groups to the scaling configuration using SecurityGroupId or SecurityGroupIds properties.",
		"zh": "在伸缩配置中使用 SecurityGroupId 或 SecurityGroupIds 属性添加安全组。",
	},
	"resource_types": ["ALIYUN::ESS::ScalingConfiguration"],
}

# Check if scaling configuration has security groups attached
has_security_group(resource) if {
	security_group_id := helpers.get_property(resource, "SecurityGroupId", "")
	security_group_id != ""
}

has_security_group(resource) if {
	security_group_ids := helpers.get_property(resource, "SecurityGroupIds", [])
	count(security_group_ids) > 0
}

# Deny rule: ESS scaling configurations must have security groups attached
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingConfiguration")
	not has_security_group(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
