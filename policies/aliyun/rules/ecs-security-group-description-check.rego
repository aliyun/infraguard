package infraguard.rules.aliyun.ecs_security_group_description_check

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "rule:aliyun:ecs-security-group-description-check",
	"name": {
		"en": "Security Group Description Not Empty",
		"zh": "安全组描述信息不能为空",
	},
	"severity": "low",
	"description": {
		"en": "Security group description should not be empty. Having a description helps with management and auditing.",
		"zh": "安全组描述信息不为空，视为合规。",
	},
	"reason": {
		"en": "The security group does not have a description, which makes it difficult to understand its purpose and manage it effectively.",
		"zh": "安全组没有描述信息，难以理解其用途并进行有效管理。",
	},
	"recommendation": {
		"en": "Add a meaningful description to the security group using the Description property to explain its purpose and usage.",
		"zh": "使用 Description 属性为安全组添加有意义的描述，说明其用途和使用场景。",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup"],
}

# Check if security group has a non-empty description
has_description(resource) if {
	helpers.has_property(resource, "Description")
	resource.Properties.Description != ""
}

# Generate deny for non-compliant resources
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	not has_description(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Description"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
