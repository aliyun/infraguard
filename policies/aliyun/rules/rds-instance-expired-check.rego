package infraguard.rules.aliyun.rds_instance_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rds-instance-expired-check",
	"name": {
		"en": "RDS Prepaid Instance Expiration Check",
		"zh": "RDS 预付费实例到期检查",
	},
	"severity": "high",
	"description": {
		"en": "Prepaid RDS instances should have auto-renewal enabled.",
		"zh": "预付费 RDS 实例应开启自动续费，避免业务中断。",
	},
	"reason": {
		"en": "The prepaid RDS instance does not have auto-renewal enabled.",
		"zh": "预付费 RDS 实例未开启自动续费。",
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid RDS instance by setting AutoRenew to true.",
		"zh": "通过将 AutoRenew 设置为 true 为预付费 RDS 实例开启自动续费。",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

is_prepaid(resource) if {
	helpers.get_property(resource, "PayType", "Postpaid") == "Prepaid"
}

# RDS AutoRenew property name is AutoRenew
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
