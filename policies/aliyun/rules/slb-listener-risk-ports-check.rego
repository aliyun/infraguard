package infraguard.rules.aliyun.slb_listener_risk_ports_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:slb-listener-risk-ports-check",
	"name": {
		"en": "SLB Listener Risk Ports Check",
		"zh": "SLB 监听禁用高风险端口"
	},
	"severity": "high",
	"description": {
		"en": "Ensures SLB listeners do not expose high-risk ports like 22 or 3389.",
		"zh": "确保 SLB 监听未暴露 22、3389 等高风险端口。"
	},
	"reason": {
		"en": "Exposing management ports to the internet via SLB increases the risk of unauthorized access.",
		"zh": "通过 SLB 向互联网暴露管理端口会增加未经授权访问的风险。"
	},
	"recommendation": {
		"en": "Use different ports for public services or use a VPN/Bastion Host for management.",
		"zh": "为公共服务使用其他端口，或使用 VPN/堡垒机进行管理。"
	},
	"resource_types": ["ALIYUN::SLB::Listener"],
}

risky_ports := [22, 3389, 3306, 6379]

is_compliant(resource) if {
	port := helpers.get_property(resource, "ListenerPort", -1)
	not helpers.includes(risky_ports, port)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ListenerPort"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
