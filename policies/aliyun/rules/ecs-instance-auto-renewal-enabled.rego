package infraguard.rules.aliyun.ecs_instance_auto_renewal_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ecs-instance-auto-renewal-enabled",
	"name": {
		"en": "ECS subscription instance has auto-renewal enabled",
		"zh": "ECS 包年包月实例开启自动续费",
	},
	"description": {
		"en": "ECS subscription (prepaid) instances have auto-renewal enabled, considered compliant. Pay-as-you-go instances are not applicable.",
		"zh": "ECS 包年包月的实例开启自动续费，视为合规。按量付费的实例不适用本规则。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::Instance"],
	"reason": {
		"en": "ECS subscription instance does not have auto-renewal enabled",
		"zh": "ECS 包年包月实例未开启自动续费",
	},
	"recommendation": {
		"en": "Enable auto-renewal for subscription instances to avoid service interruption due to expiration",
		"zh": "为订阅实例启用自动续费，避免因到期导致服务中断",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")

	# Only check subscription instances
	instance_charge_type := helpers.get_property(resource, "InstanceChargeType", "Postpaid")

	# Skip postpaid instances
	not instance_charge_type in ["Postpaid", "PayAsYouGo", "PostPaid", "PayOnDemand"]

	# For subscription instances, check if auto-renewal is enabled
	auto_renew := helpers.get_property(resource, "AutoRenew", "False")
	auto_renew == "False"

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
