package infraguard.rules.aliyun.api_gateway_api_auth_required

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:api-gateway-api-auth-required",
	"name": {
		"en": "API Gateway API Auth Required",
		"zh": "API 网关中配置 API 安全认证"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures API Gateway APIs have authentication configured.",
		"zh": "确保 API 网关中配置 API 安全认证为阿里云 APP 或使用指定的插件类型。"
	},
	"reason": {
		"en": "Authentication prevents unauthorized access to APIs.",
		"zh": "认证可防止未授权访问 API。"
	},
	"recommendation": {
		"en": "Enable authentication for all APIs.",
		"zh": "为所有 API 启用认证。"
	},
	"resource_types": ["ALIYUN::ApiGateway::Api"],
}

deny contains result if {
	some api_name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Api")
	auth_type := helpers.get_property(resource, "AuthType", "")

	auth_type == "ANONYMOUS"

	result := {
		"id": rule_meta.id,
		"resource_id": api_name,
		"violation_path": ["Properties", "AuthType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
