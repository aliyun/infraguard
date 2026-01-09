package infraguard.rules.aliyun.ess_group_health_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ess-group-health-check",
	"name": {
		"en": "ESS Scaling Group Health Check",
		"zh": "弹性伸缩组开启 ECS 实例健康检查",
	},
	"severity": "medium",
	"description": {
		"en": "ESS scaling groups should enable ECS instance health check to ensure only healthy instances are in service.",
		"zh": "弹性伸缩组开启对 ECS 实例的健康检查，视为合规。",
	},
	"reason": {
		"en": "The ESS scaling group does not have health check enabled, which may result in unhealthy instances serving traffic.",
		"zh": "弹性伸缩组未开启健康检查，可能导致异常实例仍在提供服务。",
	},
	"recommendation": {
		"en": "Enable health check type for the ESS scaling group by setting HealthCheckType to ECS or configuring HealthCheckTypes.",
		"zh": "为弹性伸缩组启用健康检查，将 HealthCheckType 设置为 ECS 或配置 HealthCheckTypes。",
	},
	"resource_types": ["ALIYUN::ESS::ScalingGroup"],
}

# Check if scaling group has health check enabled
has_health_check_enabled(resource) if {
	health_check_type := helpers.get_property(resource, "HealthCheckType", "")
	health_check_type != ""
	health_check_type != "NONE"
}

has_health_check_enabled(resource) if {
	health_check_types := helpers.get_property(resource, "HealthCheckTypes", [])
	count(health_check_types) > 0
}

# Deny rule: ESS scaling groups must have health check enabled
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingGroup")
	not has_health_check_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "HealthCheckType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
