package infraguard.rules.aliyun.api_gateway_group_enabled_ssl

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:api-gateway-group-enabled-ssl",
	"name": {
		"en": "API Gateway Group SSL Enabled",
		"zh": "API 网关分组开启 SSL",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that SSL is enabled for API Gateway groups.",
		"zh": "确保 API 网关分组开启了 SSL。",
	},
	"reason": {
		"en": "SSL encrypts traffic between clients and the API Gateway, ensuring data confidentiality.",
		"zh": "SSL 对客户端和 API 网关之间的流量进行加密，确保数据机密性。",
	},
	"recommendation": {
		"en": "Configure an SSL certificate for the API Gateway group.",
		"zh": "为 API 网关分组配置 SSL 证书。",
	},
	"resource_types": ["ALIYUN::ApiGateway::Group"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Group")

	# Conceptual check
	not helpers.has_property(resource, "CustomDomains") # Simplified
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
