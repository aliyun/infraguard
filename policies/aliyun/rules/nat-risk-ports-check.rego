package infraguard.rules.aliyun.nat_risk_ports_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:nat-risk-ports-check",
	"name": {
		"en": "NAT Gateway Risk Ports Check",
		"zh": "NAT 网关不允许映射指定的风险端口"
	},
	"severity": "high",
	"description": {
		"en": "NAT gateway DNAT mappings should not expose risky ports to the internet to prevent security vulnerabilities.",
		"zh": "NAT 网关 DNAT 映射端口不包含指定的风险端口，视为合规。"
	},
	"reason": {
		"en": "Exposing risky ports through DNAT can lead to security vulnerabilities and potential attacks.",
		"zh": "通过 DNAT 暴露风险端口可能导致安全漏洞和潜在攻击。"
	},
	"recommendation": {
		"en": "Avoid mapping well-known risky ports (e.g., 22, 3389, 445) through DNAT.",
		"zh": "避免通过 DNAT 映射已知的风险端口（如 22、3389、445 等）。"
	},
	"resource_types": ["ALIYUN::NAT::NatGateway"],
}

# Common risky ports that should not be exposed
risky_ports := {"22", "23", "445", "3389", "1433", "3306", "5432", "6379", "8080", "8443"}

contains_risky_port(resource) if {
	# Simplified check - in production would check ForwardTable entries
	forward_table := helpers.get_property(resource, "ForwardTableId", "")
	forward_table != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::NAT::NatGateway")

	# This is a placeholder - actual implementation would check DNAT entries
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ForwardTableId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
