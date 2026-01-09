package infraguard.rules.aliyun.fc_service_log_enable

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:fc-service-log-enable",
	"name": {
		"en": "FC Service Log Enable",
		"zh": "函数计算服务启用日志功能",
	},
	"severity": "medium",
	"description": {
		"en": "FC services should have logging enabled for monitoring and troubleshooting.",
		"zh": "函数计算服务启用日志功能，视为合规。",
	},
	"reason": {
		"en": "The FC service does not have logging enabled, which may affect troubleshooting and auditing.",
		"zh": "函数计算服务未启用日志功能，可能影响问题排查和审计。",
	},
	"recommendation": {
		"en": "Enable logging for the FC service by configuring LogConfig with Logstore and Project.",
		"zh": "通过配置 LogConfig（包含 Logstore 和 Project）为函数计算服务启用日志。",
	},
	"resource_types": ["ALIYUN::FC::Service"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::Service")
	log_config := helpers.get_property(resource, "LogConfig", {})
	log_config == {}
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LogConfig"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
