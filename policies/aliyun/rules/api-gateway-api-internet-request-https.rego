package infraguard.rules.aliyun.api_gateway_api_internet_request_https

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "api-gateway-api-internet-request-https",
	"name": {
		"en": "API Gateway Internet Request HTTPS Enabled",
		"zh": "API 网关公网请求开启 HTTPS",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that API Gateway APIs exposed to the internet use HTTPS protocol.",
		"zh": "确保暴露给公网的 API 网关 API 使用 HTTPS 协议。",
	},
	"reason": {
		"en": "HTTPS ensures data confidentiality and integrity during transmission over the internet.",
		"zh": "HTTPS 可确保在公网传输期间数据的机密性和完整性。",
	},
	"recommendation": {
		"en": "Configure the API Gateway API to require HTTPS for internet requests.",
		"zh": "配置 API 网关 API，要求公网请求使用 HTTPS。",
	},
	"resource_types": ["ALIYUN::ApiGateway::Api"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Api")

	# Conceptual check for protocol
	proto := helpers.get_property(resource, "RequestConfig", {"RequestProtocol": "HTTP"}).RequestProtocol
	proto == "HTTP"
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RequestConfig", "RequestProtocol"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
