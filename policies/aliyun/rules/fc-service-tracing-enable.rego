package infraguard.rules.aliyun.fc_service_tracing_enable

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:fc-service-tracing-enable",
	"name": {
		"en": "FC Service Tracing Enable",
		"zh": "函数计算服务启用链路追踪",
	},
	"severity": "medium",
	"description": {
		"en": "FC services should have tracing enabled for performance monitoring and debugging.",
		"zh": "函数计算服务启用链路追踪功能，视为合规。",
	},
	"reason": {
		"en": "The FC service does not have tracing enabled, which may affect performance analysis.",
		"zh": "函数计算服务未启用链路追踪，可能影响性能分析和问题排查。",
	},
	"recommendation": {
		"en": "Enable tracing for the FC service by configuring TracingConfig.",
		"zh": "通过配置 TracingConfig 为函数计算服务启用链路追踪。",
	},
	"resource_types": ["ALIYUN::FC::Service"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::Service")
	tracing_config := helpers.get_property(resource, "TracingConfig", {})
	tracing_config == {}
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TracingConfig"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
