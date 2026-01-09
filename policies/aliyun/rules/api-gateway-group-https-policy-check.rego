package infraguard.rules.aliyun.api_gateway_group_https_policy_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:api-gateway-group-https-policy-check",
	"name": {
		"en": "API Gateway Group HTTPS Policy Check",
		"zh": "API 网关中 API 分组的 HTTPS 安全策略满足要求"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures API Gateway groups have HTTPS security policy set correctly.",
		"zh": "确保 API 网关中的 API 分组设置的 HTTPS 安全策略在指定的参数列表中。"
	},
	"reason": {
		"en": "Strong HTTPS policies ensure secure connections.",
		"zh": "强 HTTPS 策略确保连接安全。"
	},
	"recommendation": {
		"en": "Use TLS 1.2 or higher for HTTPS connections.",
		"zh": "使用 TLS 1.2 或更高版本进行 HTTPS 连接。"
	},
	"resource_types": ["ALIYUN::ApiGateway::Group"],
}

allowed_https_policies := [
	"HTTPS2_TLS1_2",
	"HTTPS2_TLS1_3",
]

deny contains result if {
	some group_name, group_resource in helpers.resources_by_type("ALIYUN::ApiGateway::Group")

	instance_id := helpers.get_property(group_resource, "InstanceId", "")

	# Check all instances and find the one referenced by this group
	some instance_name, instance_resource in helpers.resources_by_type("ALIYUN::ApiGateway::Instance")

	# Match by direct string ID
	instance_id == instance_name
	https_policy := helpers.get_property(instance_resource, "HttpsPolicy", "")
	not https_policy in allowed_https_policies

	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties", "InstanceId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some group_name, group_resource in helpers.resources_by_type("ALIYUN::ApiGateway::Group")

	instance_id := helpers.get_property(group_resource, "InstanceId", "")

	# Check all instances and find the one referenced by this group via Fn::GetAtt
	some instance_name, instance_resource in helpers.resources_by_type("ALIYUN::ApiGateway::Instance")

	# Match by Fn::GetAtt reference
	helpers.is_get_att_referencing(instance_id, instance_name)

	https_policy := helpers.get_property(instance_resource, "HttpsPolicy", "")
	not https_policy in allowed_https_policies

	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties", "InstanceId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
