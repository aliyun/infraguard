package infraguard.rules.aliyun.ram_user_has_specified_policy

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:ram-user-has-specified-policy",
	"name": {
		"en": "RAM User Has Specified Policy",
		"zh": "RAM 用户及所属用户组绑定指定条件的权限策略"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures RAM users have the required policies attached, including those inherited from groups.",
		"zh": "确保 RAM 用户绑定了符合参数条件的权限策略，包括继承自用户组的权限。"
	},
	"reason": {
		"en": "Proper policy attachment ensures users have necessary permissions.",
		"zh": "正确绑定策略可确保用户具有必要的权限。"
	},
	"recommendation": {
		"en": "Attach the required policies to the RAM user or their groups.",
		"zh": "向 RAM 用户或其所属用户组绑定所需的策略。"
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

has_system_policy(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	system_policies != []
}

has_custom_policy(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	custom_policies := object.get(policy_attachments, "Custom", [])
	custom_policies != []
}

has_policy_via_attachment(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_referencing(user_name_val, user_name)
}

has_policy_via_attachment(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_get_att_referencing(user_name_val, user_name)
}

deny contains result if {
	some user_name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	not has_system_policy(resource)
	not has_custom_policy(resource)
	not has_policy_via_attachment(user_name)

	result := {
		"id": rule_meta.id,
		"resource_id": user_name,
		"violation_path": ["Properties", "PolicyAttachments"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
