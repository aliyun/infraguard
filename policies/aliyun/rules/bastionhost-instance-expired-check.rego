package infraguard.rules.aliyun.bastionhost_instance_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:bastionhost-instance-expired-check",
	"name": {
		"en": "BastionHost Instance Expiration Check",
		"zh": "堡垒机实例到期检查",
	},
	"severity": "high",
	"description": {
		"en": "Prepaid BastionHost instances should have auto-renewal enabled.",
		"zh": "预付费堡垒机实例应开启自动续费，避免业务中断。",
	},
	"reason": {
		"en": "The prepaid BastionHost instance does not have auto-renewal enabled.",
		"zh": "预付费堡垒机实例未开启自动续费。",
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid BastionHost instance by setting AutoRenew to true.",
		"zh": "通过将 AutoRenew 设置为 true 为预付费堡垒机实例开启自动续费。",
	},
	"resource_types": ["ALIYUN::BastionHost::Instance"],
}

is_prepaid(resource) if {
	# Check if Period is set, as it implies subscription
	helpers.has_property(resource, "Period")
}

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
