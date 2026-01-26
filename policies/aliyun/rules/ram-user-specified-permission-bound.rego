package infraguard.rules.aliyun.ram_user_specified_permission_bound

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-user-specified-permission-bound",
	"name": {
		"en": "RAM User Specified Permission Bound",
		"zh": "RAM 用户未绑定指定的高危权限"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures RAM users do not have specified high-risk permissions bound.",
		"zh": "确保 RAM 用户绑定的权限策略配置中，不包含规则入参指定的高危权限配置。"
	},
	"reason": {
		"en": "High-risk permissions can cause significant damage if misused.",
		"zh": "高危权限一旦被滥用可能造成重大损失。"
	},
	"recommendation": {
		"en": "Review and restrict user permissions to only what's necessary.",
		"zh": "审查并限制用户权限，仅授予必要的权限。"
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

high_risk_actions := [
	"ecs:DeleteInstance",
	"ecs:StopInstance",
	"oss:DeleteBucket",
	"oss:DeleteObject",
	"rds:DeleteDBInstance",
	"kms:DeleteKey",
	"ram:DeleteUser",
	"ram:DeletePolicy",
]

is_admin_policy_name(policy_name) if {
	policy_name == "AdministratorAccess"
}

is_admin_policy_name(policy_name) if {
	contains(policy_name, "FullAccess")
	contains(policy_name, "Admin")
}

has_admin_system_policy(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	some policy in system_policies
	is_admin_policy_name(policy)
}

has_admin_custom_policy(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	custom_policies := object.get(policy_attachments, "Custom", [])
	some policy in custom_policies
	is_admin_policy_name(policy)
}

has_admin_policy_via_attachment(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_referencing(user_name_val, user_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	is_admin_policy_name(policy_name)
}

has_admin_policy_via_attachment(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_get_att_referencing(user_name_val, user_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	is_admin_policy_name(policy_name)
}

# Get high risk actions from parameter or default
get_high_risk_actions := actions if {
	actions := input.parameters.highRiskActions
	is_array(actions)
} else := high_risk_actions

# Check inline policies for high risk actions
has_inline_high_risk_permission(resource) if {
	policies := helpers.get_property(resource, "Policies", [])
	some policy in policies
	doc := object.get(policy, "PolicyDocument", {})

	statements := object.get(doc, "Statement", [])
	some statement in statements
	effect := object.get(statement, "Effect", "")
	effect == "Allow"

	actions := to_list(object.get(statement, "Action", []))
	required_risks := get_high_risk_actions

	some action in actions
	some risk in required_risks
	action == risk
}

to_list(v) := v if is_array(v)
to_list(v) := [v] if is_string(v)

deny contains result if {
	some user_name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	has_inline_high_risk_permission(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": user_name,
		"violation_path": ["Properties", "Policies"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some user_name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	has_admin_system_policy(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": user_name,
		"violation_path": ["Properties", "PolicyAttachments", "System"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some user_name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	has_admin_custom_policy(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": user_name,
		"violation_path": ["Properties", "PolicyAttachments", "Custom"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some user_name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	has_admin_policy_via_attachment(user_name)

	result := {
		"id": rule_meta.id,
		"resource_id": user_name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
