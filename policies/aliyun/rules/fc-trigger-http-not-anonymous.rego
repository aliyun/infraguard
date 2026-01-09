package infraguard.rules.aliyun.fc_trigger_http_not_anonymous

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:fc-trigger-http-not-anonymous",
	"name": {
		"en": "FC HTTP Trigger Authentication Check",
		"zh": "函数 HTTP 触发器设置为需要身份验证",
	},
	"severity": "high",
	"description": {
		"en": "FC HTTP triggers should require authentication to prevent unauthorized access.",
		"zh": "函数 HTTP 触发器配置为需要身份验证，视为合规。",
	},
	"reason": {
		"en": "The FC HTTP trigger allows anonymous access, which may expose the function to unauthorized invocations.",
		"zh": "函数 HTTP 触发器允许匿名访问，可能导致未经授权的函数调用。",
	},
	"recommendation": {
		"en": "Configure authentication for the HTTP trigger by setting appropriate authorization type.",
		"zh": "为 HTTP 触发器配置适当的授权类型以启用身份验证。",
	},
	"resource_types": ["ALIYUN::FC::Trigger"],
}

# Check if trigger is HTTP type and allows anonymous access
is_anonymous_http_trigger(resource) if {
	trigger_type := helpers.get_property(resource, "TriggerType", "")
	trigger_type == "http"
	trigger_config := helpers.get_property(resource, "TriggerConfig", {})
	auth_type := object.get(trigger_config, "AuthType", "")
	auth_type == "anonymous"
}

# Deny rule: HTTP triggers should not allow anonymous access
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::Trigger")
	is_anonymous_http_trigger(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TriggerConfig", "AuthType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
