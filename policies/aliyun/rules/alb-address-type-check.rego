package infraguard.rules.aliyun.alb_address_type_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "alb-address-type-check",
	"name": {
		"en": "ALB Address Type Check",
		"zh": "ALB 网络类型核查"
	},
	"severity": "low",
	"description": {
		"en": "Ensures ALB instances use the preferred address type (e.g., Intranet).",
		"zh": "确保 ALB 实例使用首选的网络类型（如私网）。"
	},
	"reason": {
		"en": "Internal-only services should be placed on an Intranet ALB to reduce exposure.",
		"zh": "仅限内部使用的服务应放置在私网 ALB 上以减少暴露。"
	},
	"recommendation": {
		"en": "Set AddressType to 'Intranet' for internal services.",
		"zh": "为内部服务将 AddressType 设置为 'Intranet'。"
	},
	"resource_types": ["ALIYUN::ALB::LoadBalancer"],
}

is_compliant(resource) if {
	# Example: check if it's Intranet
	helpers.get_property(resource, "AddressType", "") == "Intranet"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AddressType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
