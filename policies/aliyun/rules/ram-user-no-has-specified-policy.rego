package infraguard.rules.aliyun.ram_user_no_has_specified_policy

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:ram-user-no-has-specified-policy",
	"name": {
		"en": "RAM User No Specified Policy",
		"zh": "RAM 用户及所属用户组未绑定指定条件的权限策略"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures RAM users do not have specified risky policies attached.",
		"zh": "确保 RAM 用户未绑定符合参数条件的高危权限策略。"
	},
	"reason": {
		"en": "Risky policies increase the attack surface.",
		"zh": "高危策略会增加攻击面。"
	},
	"recommendation": {
		"en": "Remove or replace risky policies with least privilege alternatives.",
		"zh": "移除或替换高危策略，使用最小权限的替代方案。"
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

risky_policies := [
	"AdministratorAccess",
	"*:*",
]

is_admin_policy(policy_name) if {
	policy_name == "AdministratorAccess"
}

is_admin_policy(policy_name) if {
	policy_name == "*"
}

has_risky_system_policy(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	some policy in system_policies
	is_admin_policy(policy)
}

has_risky_system_policy(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	some policy in system_policies
	policy in risky_policies
}

has_risky_policy_via_attachment(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_referencing(user_name_val, user_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	is_admin_policy(policy_name)
}

has_risky_policy_via_attachment(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_referencing(user_name_val, user_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	policy_name in risky_policies
}

has_risky_policy_via_attachment(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_get_att_referencing(user_name_val, user_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	is_admin_policy(policy_name)
}

has_risky_policy_via_attachment(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_get_att_referencing(user_name_val, user_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	policy_name in risky_policies
}

deny contains result if {
	some user_name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	has_risky_system_policy(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": user_name,
		"violation_path": ["Properties", "PolicyAttachments", "System"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some user_name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	has_risky_policy_via_attachment(user_name)

	result := {
		"id": rule_meta.id,
		"resource_id": user_name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
