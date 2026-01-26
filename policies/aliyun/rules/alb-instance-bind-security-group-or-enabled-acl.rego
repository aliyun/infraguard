package infraguard.rules.aliyun.alb_instance_bind_security_group_or_enabled_acl

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "alb-instance-bind-security-group-or-enabled-acl",
	"name": {
		"en": "ALB Instance Bind Security Group or Enable ACL",
		"zh": "ALB 实例关联安全组或者为所有监听设置访问控制",
	},
	"severity": "medium",
	"description": {
		"en": "ALB instance should have security groups associated or ACL configured for all running listeners.",
		"zh": "ALB 实例关联了安全组或者为所有运行中的监听都设置了访问控制，视为合规。不存在运行中监听的实例不适用本规则，视为不适用。",
	},
	"reason": {
		"en": "ALB instance does not have security groups associated, which may expose the load balancer to security risks.",
		"zh": "ALB 实例未关联安全组，可能导致负载均衡器面临安全风险。",
	},
	"recommendation": {
		"en": "Associate security groups with the ALB instance by configuring SecurityGroupIds property, or set up ACL for all listeners.",
		"zh": "通过配置 SecurityGroupIds 属性为 ALB 实例关联安全组，或为所有监听器设置访问控制列表(ACL)。",
	},
	"resource_types": ["ALIYUN::ALB::LoadBalancer"],
}

# Check if security groups are configured
has_security_groups(resource) if {
	count(resource.Properties.SecurityGroupIds) > 0
}

# Generate deny for non-compliant resources
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::LoadBalancer")
	not has_security_groups(resource)
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
