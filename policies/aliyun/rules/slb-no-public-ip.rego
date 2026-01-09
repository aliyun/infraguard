package infraguard.rules.aliyun.slb_no_public_ip

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:slb-no-public-ip",
	"name": {
		"en": "SLB Instance No Public IP",
		"zh": "SLB 实例未开启公网访问"
	},
	"severity": "medium",
	"description": {
		"en": "SLB instances should not have public IP addresses to reduce attack surface.",
		"zh": "SLB 实例网络类型为内网，视为合规。"
	},
	"reason": {
		"en": "Publicly accessible SLB instances increase the attack surface and may expose services to unwanted internet traffic.",
		"zh": "可公开访问的 SLB 实例增加了攻击面，可能将服务暴露给非预期的互联网流量。"
	},
	"recommendation": {
		"en": "Use intranet-facing SLB instances for internal services.",
		"zh": "对内部服务使用内网类型的 SLB 实例。"
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

is_internal(resource) if {
	address_type := helpers.get_property(resource, "AddressType", "")
	address_type == "intranet"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_internal(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AddressType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
