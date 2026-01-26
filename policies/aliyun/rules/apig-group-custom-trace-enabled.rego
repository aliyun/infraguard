package infraguard.rules.aliyun.apig_group_custom_trace_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "apig-group-custom-trace-enabled",
	"name": {
		"en": "API Gateway Group Custom Trace Enabled",
		"zh": "API 分组自定义追踪启用"
	},
	"severity": "low",
	"description": {
		"en": "Ensures API Gateway groups have custom tracing enabled.",
		"zh": "确保 API 网关分组启用了自定义追踪功能。"
	},
	"reason": {
		"en": "Custom tracing enables better debugging and performance analysis.",
		"zh": "自定义追踪可实现更好的调试和性能分析。"
	},
	"recommendation": {
		"en": "Enable custom tracing for API Gateway groups.",
		"zh": "为 API 网关分组启用自定义追踪。"
	},
	"resource_types": ["ALIYUN::ApiGateway::Group"],
}

deny contains result if {
	some group_name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Group")

	not has_tracing_enabled(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

has_tracing_enabled(resource) if {
	tags := helpers.get_property(resource, "Tags", [])
	some tag in tags
	tag.Key == "TracingEnabled"
	tag.Value == "true"
}

has_tracing_enabled(resource) if {
	some name, config in helpers.resources_by_type("ALIYUN::ApiGateway::Tracing")
	group_id := helpers.get_property(config, "GroupId", "")
	resource_group_id := helpers.get_property(resource, "GroupId", "")
	group_id == resource_group_id
}
