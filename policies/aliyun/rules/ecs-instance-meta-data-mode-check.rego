package infraguard.rules.aliyun.ecs_instance_meta_data_mode_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ecs-instance-meta-data-mode-check",
	"name": {
		"en": "ECS instance metadata access uses security-enhanced mode (IMDSv2)",
		"zh": "访问 ECS 实例元数据时强制使用加固模式",
	},
	"description": {
		"en": "When accessing ECS instance metadata, security-enhanced mode (IMDSv2) is enforced, considered compliant. Instances associated with ACK clusters are not applicable.",
		"zh": "访问 ECS 实例元数据时强制使用加固模式，视为合规。ACK 集群关联的实例视为不适用。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::Instance"],
	"reason": {
		"en": "ECS instance metadata is accessible without security-enhanced mode (IMDSv1)",
		"zh": "ECS 实例元数据可在未启用加固模式(IMDSv1)的情况下访问",
	},
	"recommendation": {
		"en": "Set HttpEndpoint to 'enabled' and HttpTokens to 'required' to enforce IMDSv2",
		"zh": "将 HttpEndpoint 设置为 'enabled'，并将 HttpTokens 设置为 'required' 以强制使用 IMDSv2",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")

	# Check if metadata endpoint is enabled
	http_endpoint := helpers.get_property(resource, "HttpEndpoint", "enabled")

	# If endpoint is disabled, metadata access is not possible
	http_endpoint == "disabled"

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "HttpEndpoint"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")

	# If endpoint is not disabled, check if tokens are required (IMDSv2)
	http_endpoint := helpers.get_property(resource, "HttpEndpoint", "enabled")
	http_endpoint != "disabled"

	http_tokens := helpers.get_property(resource, "HttpTokens", "optional")
	http_tokens == "optional"

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "HttpTokens"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
