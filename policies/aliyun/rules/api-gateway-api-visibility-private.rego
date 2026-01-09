package infraguard.rules.aliyun.api_gateway_api_visibility_private

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:api-gateway-api-visibility-private",
	"name": {
		"en": "API Gateway API Visibility Private",
		"zh": "API 网关中的 API 设置为私有"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures API Gateway APIs are set to PRIVATE visibility.",
		"zh": "确保 API 网关中的 API 设置为私有。"
	},
	"reason": {
		"en": "Private APIs are only accessible within the VPC, reducing exposure.",
		"zh": "私有 API 只能在 VPC 内访问，减少暴露面。"
	},
	"recommendation": {
		"en": "Set API visibility to PRIVATE for internal APIs.",
		"zh": "将内部 API 的可见性设置为私有。"
	},
	"resource_types": ["ALIYUN::ApiGateway::Api"],
}

deny contains result if {
	some api_name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Api")
	visibility := helpers.get_property(resource, "Visibility", "")

	visibility == "PUBLIC"

	result := {
		"id": rule_meta.id,
		"resource_id": api_name,
		"violation_path": ["Properties", "Visibility"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
