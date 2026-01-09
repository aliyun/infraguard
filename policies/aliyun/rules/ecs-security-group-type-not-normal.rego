package infraguard.rules.aliyun.ecs_security_group_type_not_normal

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "rule:aliyun:ecs-security-group-type-not-normal",
	"name": {
		"en": "Use Enterprise Security Group Type",
		"zh": "使用企业类型安全组",
	},
	"severity": "low",
	"description": {
		"en": "ECS security group type should not be normal type. Using enterprise security group is considered compliant.",
		"zh": "ECS 安全组类型非普通安全组，视为合规。",
	},
	"reason": {
		"en": "The security group is using normal type instead of enterprise type, which may have limitations in functionality and performance.",
		"zh": "安全组使用了普通类型而非企业类型，可能在功能和性能上存在限制。",
	},
	"recommendation": {
		"en": "Set SecurityGroupType property to 'enterprise' to use enterprise security group which provides better performance and more features.",
		"zh": "将 SecurityGroupType 属性设置为'enterprise'以使用企业安全组，获得更好的性能和更多功能。",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup"],
}

# Check if security group uses enterprise type
is_enterprise_type(resource) if {
	resource.Properties.SecurityGroupType == "enterprise"
}

# Generate deny for non-compliant resources (normal type or not specified)
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	not is_enterprise_type(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
