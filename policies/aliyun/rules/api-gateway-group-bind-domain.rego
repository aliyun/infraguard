package infraguard.rules.aliyun.api_gateway_group_bind_domain

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "api-gateway-group-bind-domain",
	"name": {
		"en": "API Gateway Group Bind Domain",
		"zh": "API 网关中 API 分组绑定自定义域名"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures API Gateway groups have custom domains bound.",
		"zh": "确保 API 网关中的 API 分组绑定了自定义域名。"
	},
	"reason": {
		"en": "Custom domains provide better branding and control.",
		"zh": "自定义域名提供更好的品牌控制和可管理性。"
	},
	"recommendation": {
		"en": "Bind custom domains to API Gateway groups.",
		"zh": "为 API 网关分组绑定自定义域名。"
	},
	"resource_types": ["ALIYUN::ApiGateway::Group"],
}

deny contains result if {
	some group_name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Group")

	not has_custom_domain_bound(group_name, resource)

	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

has_custom_domain_bound(group_name, group_resource) if {
	some domain_name, domain_resource in helpers.resources_by_type("ALIYUN::ApiGateway::CustomDomain")
	bound_group_id := helpers.get_property(domain_resource, "GroupId", "")
	group_id := helpers.get_property(group_resource, "GroupId", "")

	# Handle direct string match
	bound_group_id == group_id
}

has_custom_domain_bound(group_name, group_resource) if {
	some domain_name, domain_resource in helpers.resources_by_type("ALIYUN::ApiGateway::CustomDomain")
	bound_group_id := helpers.get_property(domain_resource, "GroupId", "")

	# Handle Fn::GetAtt reference - check if it references the group
	helpers.is_get_att_referencing(bound_group_id, group_name)
}
