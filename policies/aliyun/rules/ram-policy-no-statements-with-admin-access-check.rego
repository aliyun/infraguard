package infraguard.rules.aliyun.ram_policy_no_statements_with_admin_access_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-policy-no-statements-with-admin-access-check",
	"name": {
		"en": "RAM Policy No Admin Access",
		"zh": "禁止 RAM 策略包含管理员权限"
	},
	"severity": "high",
	"description": {
		"en": "Ensures custom RAM policies do not grant full AdministratorAccess.",
		"zh": "确保自定义 RAM 策略未授予完全的管理员权限（AdministratorAccess）。"
	},
	"reason": {
		"en": "Granting excessive permissions increases the impact of a compromised account.",
		"zh": "授予过高权限会增加账号被盗后的危害。"
	},
	"recommendation": {
		"en": "Follow the principle of least privilege. Do not use '*' for both Action and Resource in the same statement.",
		"zh": "遵循最小权限原则。不要在同一条语句中对 Action 和 Resource 同时使用 '*'。"
	},
	"resource_types": ["ALIYUN::RAM::ManagedPolicy"],
}

is_compliant(resource) if {
	doc := helpers.get_property(resource, "PolicyDocument", {})
	statements := object.get(doc, "Statement", [])
	not has_admin_statement(statements)
}

has_admin_statement(statements) if {
	some statement in statements
	statement.Effect == "Allow"
	is_all(statement.Action)
	is_all(statement.Resource)
}

is_all("*") := true

is_all(a) if {
	is_array(a)
	some item in a
	item == "*"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::ManagedPolicy")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "PolicyDocument"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
