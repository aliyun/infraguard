package infraguard.rules.aliyun.ecs_internet_charge_type_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ecs-internet-charge-type-check",
	"name": {
		"en": "ECS Internet Charge Type Check",
		"zh": "ECS 公网带宽计费方式核查"
	},
	"severity": "low",
	"description": {
		"en": "Ensures ECS instances use the preferred internet charge type.",
		"zh": "确保 ECS 实例使用首选的公网带宽计费方式。"
	},
	"reason": {
		"en": "Consistent charge types help in predictable billing and cost management.",
		"zh": "一致的计费方式有助于实现可预测的账单和成本管理。"
	},
	"recommendation": {
		"en": "Set InternetChargeType to 'PayByTraffic'.",
		"zh": "将 InternetChargeType 设置为'PayByTraffic'。"
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

is_compliant(resource) if {
	charge_type := helpers.get_property(resource, "InternetChargeType", "PayByTraffic")
	charge_type == "PayByTraffic"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "InternetChargeType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
