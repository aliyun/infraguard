package infraguard.rules.aliyun.ecs_instance_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ecs-instance-expired-check",
	"name": {
		"en": "ECS Prepaid Instance Expiration Check",
		"zh": "ECS 预付费实例到期检查",
	},
	"severity": "high",
	"description": {
		"en": "Prepaid instances should have auto-renewal enabled to avoid service interruption due to expiration.",
		"zh": "预付费实例应开启自动续费，避免出现因费用问题停机。",
	},
	"reason": {
		"en": "The prepaid ECS instance does not have auto-renewal enabled.",
		"zh": "预付费 ECS 实例未开启自动续费。",
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid ECS instance by setting AutoRenew to true.",
		"zh": "通过将 AutoRenew 设置为 true 为预付费 ECS 实例开启自动续费。",
	},
	"resource_types": ["ALIYUN::ECS::Instance"],
}

# Check if instance is Prepaid
is_prepaid(resource) if {
	# Check InstanceChargeType
	charge_type := helpers.get_property(resource, "InstanceChargeType", "PostPaid")
	charge_type == "PrePaid"
}

# Check if AutoRenew is enabled
is_auto_renew_enabled(resource) if {
	auto_renew := helpers.get_property(resource, "AutoRenew", false)
	helpers.is_true(auto_renew)
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	is_prepaid(resource)
	not is_auto_renew_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AutoRenew"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
