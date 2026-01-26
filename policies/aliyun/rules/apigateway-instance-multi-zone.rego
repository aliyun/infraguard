package infraguard.rules.aliyun.apigateway_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "apigateway-instance-multi-zone",
	"name": {
		"en": "API Gateway Instance Multi-Zone Deployment",
		"zh": "使用多可用区的 API 网关实例",
	},
	"severity": "medium",
	"description": {
		"en": "API Gateway instances should be deployed in multi-zone configuration for high availability.",
		"zh": "使用多可用区的 API 网关实例，视为合规。",
	},
	"reason": {
		"en": "The API Gateway instance is deployed in a single availability zone, creating a single point of failure.",
		"zh": "API 网关实例部署在单个可用区，存在单点故障风险。",
	},
	"recommendation": {
		"en": "Deploy the API Gateway instance in a multi-zone configuration by specifying a ZoneId with MAZ (Multi-AZ) format, such as 'cn-beijing-MAZ2(f,g)'.",
		"zh": "通过指定 MAZ（多可用区）格式的 ZoneId（如'cn-beijing-MAZ2(f,g)'），将 API 网关实例部署在多可用区配置中。",
	},
	"resource_types": ["ALIYUN::ApiGateway::Instance"],
}

# Check if zone ID indicates multi-zone deployment
# Multi-zone format: cn-region-MAZ#(zone1,zone2,...)
is_multi_zone(zone_id) if {
	contains(zone_id, "MAZ")
	contains(zone_id, "(")
	contains(zone_id, ")")
}

# Check if instance is multi-zone
has_multi_zone_deployment(resource) if {
	zone_id := resource.Properties.ZoneId
	is_multi_zone(zone_id)
}

# Deny rule: API Gateway instances must be multi-zone
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Instance")
	not has_multi_zone_deployment(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ZoneId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
