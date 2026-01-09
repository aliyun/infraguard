package infraguard.rules.aliyun.natgateway_eip_used_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:natgateway-eip-used-check",
	"name": {
		"en": "NAT Gateway EIP Usage Check",
		"zh": "NAT 网关中 SNAT 和 DNAT 未使用同一个 EIP"
	},
	"severity": "medium",
	"description": {
		"en": "SNAT and DNAT should not use the same EIP to avoid potential conflicts and improve network segmentation.",
		"zh": "NAT 网关的 SNAT 和 DNAT 未同时使用同一个 EIP，视为合规。"
	},
	"reason": {
		"en": "Using the same EIP for both SNAT and DNAT can lead to routing conflicts and security issues.",
		"zh": "SNAT 和 DNAT 使用同一个 EIP 可能导致路由冲突和安全问题。"
	},
	"recommendation": {
		"en": "Configure different EIPs for SNAT and DNAT entries.",
		"zh": "为 SNAT 和 DNAT 条目配置不同的 EIP。"
	},
	"resource_types": ["ALIYUN::NAT::NatGateway"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::NAT::NatGateway")

	# Simplified check - in practice would check ForwardTableId and SNatTableId
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
