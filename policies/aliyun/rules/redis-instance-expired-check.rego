package infraguard.rules.aliyun.redis_instance_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:redis-instance-expired-check",
	"name": {
		"en": "Redis Prepaid Instance Expiration Check",
		"zh": "Redis 预付费实例到期检查",
	},
	"severity": "high",
	"description": {
		"en": "Prepaid Redis instances should have auto-renewal enabled.",
		"zh": "预付费 Redis 实例应开启自动续费，避免业务中断。",
	},
	"reason": {
		"en": "The prepaid Redis instance does not have auto-renewal enabled.",
		"zh": "预付费 Redis 实例未开启自动续费。",
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid Redis instance by setting AutoRenewDuration.",
		"zh": "通过设置 AutoRenewDuration 为预付费 Redis 实例开启自动续费。",
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_prepaid(resource) if {
	helpers.get_property(resource, "ChargeType", "PostPaid") == "PrePaid"
}

# Redis uses AutoRenewDuration for auto-renewal configuration
is_auto_renew_enabled(resource) if {
	duration := helpers.get_property(resource, "AutoRenewDuration", 0)
	duration > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	is_prepaid(resource)
	not is_auto_renew_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AutoRenewDuration"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
