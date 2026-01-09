package infraguard.rules.aliyun.fc_service_bind_role

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:fc-service-bind-role",
	"name": {
		"en": "FC Service Bound to RAM Role",
		"zh": "FC 服务绑定角色",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the Function Compute service has a RAM role bound to it.",
		"zh": "确保函数计算服务绑定了 RAM 角色。",
	},
	"reason": {
		"en": "Binding a RAM role to an FC service allows the function to securely access other Alibaba Cloud resources.",
		"zh": "为 FC 服务绑定 RAM 角色允许函数安全地访问其他阿里云资源。",
	},
	"recommendation": {
		"en": "Bind a RAM role to the Function Compute service.",
		"zh": "为函数计算服务绑定 RAM 角色。",
	},
	"resource_types": ["ALIYUN::FC::Service"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::Service")
	not helpers.has_property(resource, "Role")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Role"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
