package infraguard.rules.aliyun.ram_user_role_no_product_admin_access

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-user-role-no-product-admin-access",
	"name": {
		"en": "RAM User Role No Product Admin Access",
		"zh": "ram 用户定义的角色不包括产品管理权限"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures RAM user-defined roles do not have product administrative permissions.",
		"zh": "确保 RAM 用户创建的角色未拥有管理员权限或者某个云产品的管理员权限。"
	},
	"reason": {
		"en": "Custom roles with admin permissions increase security risks.",
		"zh": "具有管理权限的自定义角色会增加安全风险。"
	},
	"recommendation": {
		"en": "Review role permissions and remove excessive privileges.",
		"zh": "审查角色权限并移除过多的权限。"
	},
	"resource_types": ["ALIYUN::RAM::Role"],
}

is_service_linked_role(policy_doc) if {
	statements := object.get(policy_doc, "Statement", [])
	some statement in statements
	effect := object.get(statement, "Effect", "")
	effect == "Allow"

	principal := object.get(statement, "Principal", {})
	services := object.get(principal, "Service", [])

	some service in services
	contains(service, ".aliyuncs.com")
}

has_admin_access(resource) if {
	policies := helpers.get_property(resource, "Policies", [])
	some policy_def in policies
	doc := object.get(policy_def, "PolicyDocument", {})

	statements := object.get(doc, "Statement", [])
	some statement in statements
	effect := object.get(statement, "Effect", "")
	effect == "Allow"

	actions := object.get(statement, "Action", [])
	resources := object.get(statement, "Resource", [])

	is_wildcard(actions)
	is_wildcard(resources)
}

has_admin_access(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	some policy in system_policies
	policy == "AdministratorAccess"
}

has_admin_access_via_attachment(role_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToRole")
	role_name_val := helpers.get_property(resource, "RoleName", "")
	helpers.is_referencing(role_name_val, role_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	policy_name == "AdministratorAccess"
}

has_admin_access_via_attachment(role_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToRole")
	role_name_val := helpers.get_property(resource, "RoleName", "")
	helpers.is_get_att_referencing(role_name_val, role_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	policy_name == "AdministratorAccess"
}

has_admin_access_via_attachment(role_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToRole")
	role_name_val := helpers.get_property(resource, "RoleName", "")
	role_resource := helpers.resources_by_type("ALIYUN::RAM::Role")[role_name]
	actual_name := helpers.get_property(role_resource, "RoleName", role_name)
	role_name_val == actual_name
	policy_name := helpers.get_property(resource, "PolicyName", "")
	policy_name == "AdministratorAccess"
}

is_wildcard("*") := true
is_wildcard(["*"]) := true

is_wildcard(arr) if {
	is_array(arr)
	some item in arr
	item == "*"
}

deny contains result if {
	some role_name, resource in helpers.resources_by_type("ALIYUN::RAM::Role")

	policy_doc := helpers.get_property(resource, "AssumeRolePolicyDocument", {})
	not is_service_linked_role(policy_doc)

	has_admin_access(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": role_name,
		"violation_path": ["Properties", "PolicyDocument"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some role_name, resource in helpers.resources_by_type("ALIYUN::RAM::Role")

	policy_doc := helpers.get_property(resource, "AssumeRolePolicyDocument", {})
	not is_service_linked_role(policy_doc)

	has_admin_access_via_attachment(role_name)

	result := {
		"id": rule_meta.id,
		"resource_id": role_name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
