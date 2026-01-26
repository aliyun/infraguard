package infraguard.rules.aliyun.api_gateway_group_log_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "api-gateway-group-log-enabled",
	"name": {
		"en": "API Gateway Group Log Enabled",
		"zh": "为 API 分组设置调用日志存储"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures API Gateway groups have logging configured.",
		"zh": "确保 API 网关中 API 分组设置了调用日志存储。"
	},
	"reason": {
		"en": "Logging enables monitoring and troubleshooting of API usage.",
		"zh": "日志记录可实现 API 使用的监控和故障排除。"
	},
	"recommendation": {
		"en": "Enable logging for API Gateway groups.",
		"zh": "为 API 网关分组启用日志记录。"
	},
	"resource_types": ["ALIYUN::ApiGateway::Group"],
}

deny contains result if {
	some group_name, group_resource in helpers.resources_by_type("ALIYUN::ApiGateway::Group")

	not has_log_config(group_name, group_resource)

	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

has_log_config(group_name, group_resource) if {
	some log_resource in helpers.resources_by_type("ALIYUN::ApiGateway::LogConfig")
	bound_group_id := helpers.get_property(log_resource, "GroupId", "")

	# Handle direct string match
	bound_group_id == group_name

	log_store := helpers.get_property(log_resource, "LogStore", "")
	log_store != ""
}

has_log_config(group_name, group_resource) if {
	some log_resource in helpers.resources_by_type("ALIYUN::ApiGateway::LogConfig")
	bound_group_id := helpers.get_property(log_resource, "GroupId", "")

	# Handle Fn::GetAtt reference
	helpers.is_get_att_referencing(bound_group_id, group_name)

	log_store := helpers.get_property(log_resource, "LogStore", "")
	log_store != ""
}

has_log_config(group_name, group_resource) if {
	some log_resource in helpers.resources_by_type("ALIYUN::ApiGateway::LogConfig")
	bound_group_id := helpers.get_property(log_resource, "GroupId", "")

	# Handle direct string match
	bound_group_id == group_name

	sls_log_store := helpers.get_property(log_resource, "SlsLogStore", "")
	sls_log_store != ""
}

has_log_config(group_name, group_resource) if {
	some log_resource in helpers.resources_by_type("ALIYUN::ApiGateway::LogConfig")
	bound_group_id := helpers.get_property(log_resource, "GroupId", "")

	# Handle Fn::GetAtt reference
	helpers.is_get_att_referencing(bound_group_id, group_name)

	sls_log_store := helpers.get_property(log_resource, "SlsLogStore", "")
	sls_log_store != ""
}

has_log_config(group_name, group_resource) if {
	tags := helpers.get_property(group_resource, "Tags", [])
	some tag in tags
	tag.Key == "LogEnabled"
	tag.Value == "true"
}
