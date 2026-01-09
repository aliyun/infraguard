package infraguard.rules.aliyun.api_gateway_api_auth_jwt

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:api-gateway-api-auth-jwt",
	"name": {
		"en": "API Gateway API Auth JWT",
		"zh": "API 网关中 API 安全认证设置为 JWT 方式"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures API Gateway APIs use JWT authentication.",
		"zh": "确保 API 网关中的 API 安全认证为 JWT 方式。"
	},
	"reason": {
		"en": "JWT provides secure authentication for API access.",
		"zh": "JWT 为 API 访问提供安全的认证机制。"
	},
	"recommendation": {
		"en": "Configure JWT authentication for APIs.",
		"zh": "为 API 配置 JWT 认证。"
	},
	"resource_types": ["ALIYUN::ApiGateway::Api"],
}

deny contains result if {
	some api_name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Api")
	auth_type := helpers.get_property(resource, "AuthType", "")

	not auth_type == "APPOPENID"

	result := {
		"id": rule_meta.id,
		"resource_id": api_name,
		"violation_path": ["Properties", "AuthType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some api_name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Api")
	auth_type := helpers.get_property(resource, "AuthType", "")

	auth_type == "APPOPENID"

	open_id_config := helpers.get_property(resource, "OpenIdConnectConfig", {})
	open_id_api_type := object.get(open_id_config, "OpenIdApiType", "")

	not open_id_api_type == "IDTOKEN"

	result := {
		"id": rule_meta.id,
		"resource_id": api_name,
		"violation_path": ["Properties", "OpenIdConnectConfig", "OpenIdApiType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
