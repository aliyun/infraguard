package infraguard.rules.aliyun.mongodb_cluster_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:mongodb-cluster-expired-check",
	"name": {
		"en": "MongoDB Instance Expiration Check",
		"zh": "MongoDB 实例到期检查",
	},
	"severity": "high",
	"description": {
		"en": "Prepaid MongoDB instances should have auto-renewal enabled.",
		"zh": "预付费 MongoDB 实例应开启自动续费，避免业务中断。",
	},
	"reason": {
		"en": "The prepaid MongoDB instance does not have auto-renewal enabled.",
		"zh": "预付费 MongoDB 实例未开启自动续费。",
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid MongoDB instance by setting AutoRenew to true.",
		"zh": "通过将 AutoRenew 设置为 true 为预付费 MongoDB 实例开启自动续费。",
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

is_prepaid(resource) if {
	helpers.get_property(resource, "ChargeType", "PostPaid") == "PrePaid"
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
