package infraguard.rules.aliyun.ess_scaling_configuration_sg_public_access

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ess-scaling-configuration-sg-public-access",
	"name": {
		"en": "ESS Scaling Configuration Security Group Public Access",
		"zh": "ESS 伸缩组配置的安全组不应设置为 0.0.0.0/0",
	},
	"severity": "high",
	"description": {
		"en": "ESS scaling configuration security groups should not allow access from 0.0.0.0/0 to prevent unauthorized access.",
		"zh": "ESS 伸缩组配置中的安全组不包含 0.0.0.0/0，则视为合规。",
	},
	"reason": {
		"en": "The ESS scaling configuration's security group allows access from 0.0.0.0/0, which may expose instances to the public internet.",
		"zh": "ESS 伸缩组配置的安全组规则中允许 0.0.0.0/0 访问，可能导致实例暴露于公网。",
	},
	"recommendation": {
		"en": "Restrict security group rules to specific IP ranges instead of 0.0.0.0/0.",
		"zh": "将安全组规则限制为特定 IP 范围，避免使用 0.0.0.0/0。",
	},
	"resource_types": ["ALIYUN::ESS::ScalingConfiguration"],
}

has_security_group(resource) if {
	security_group_id := helpers.get_property(resource, "SecurityGroupId", "")
	security_group_id != ""
}

has_security_group(resource) if {
	security_group_ids := helpers.get_property(resource, "SecurityGroupIds", [])
	count(security_group_ids) > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingConfiguration")
	not has_security_group(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": "The scaling configuration does not have explicit security groups configured.",
			"recommendation": "Configure specific security groups for the scaling configuration.",
		},
	}
}
