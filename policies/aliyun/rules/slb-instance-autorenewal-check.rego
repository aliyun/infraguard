package infraguard.rules.aliyun.slb_instance_autorenewal_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:slb-instance-autorenewal-check",
	"name": {
		"en": "SLB Instance Auto-Renewal Check",
		"zh": "SLB 实例包年包月开启自动续费"
	},
	"severity": "medium",
	"description": {
		"en": "Prepaid SLB instances should have auto-renewal enabled to avoid service interruption.",
		"zh": "包年包月的 SLB 实例开启了自动续费，视为合规。"
	},
	"reason": {
		"en": "SLB instances without auto-renewal may expire and cause service interruption.",
		"zh": "未开启自动续费的 SLB 实例可能到期并导致服务中断。"
	},
	"recommendation": {
		"en": "Enable auto-renewal for prepaid SLB instances.",
		"zh": "为包年包月 SLB 实例开启自动续费。"
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

is_prepaid(resource) if {
	charge_type := helpers.get_property(resource, "InstanceChargeType", "")
	charge_type == "Prepaid"
}

has_autorenewal(resource) if {
	auto_renew := helpers.get_property(resource, "AutoRenew", false)
	auto_renew == true
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	is_prepaid(resource)
	not has_autorenewal(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AutoRenew"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
