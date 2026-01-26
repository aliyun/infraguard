package infraguard.rules.aliyun.slb_all_listenter_has_server

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-all-listenter-has-server",
	"name": {
		"en": "SLB All Listeners Have Backend Servers",
		"zh": "SLB 负载均衡的所有监听都至少添加了指定数量的后端服务器"
	},
	"severity": "medium",
	"description": {
		"en": "All listeners of SLB instances should have at least the specified number of backend servers attached.",
		"zh": "SLB 负载均衡的所有监听都至少添加参数指定数量的后端服务器，视为合规。默认至少添加一台服务器视为合规。"
	},
	"reason": {
		"en": "Listeners without backend servers cannot forward traffic, leading to service unavailability.",
		"zh": "没有后端服务器的监听无法转发流量，导致服务不可用。"
	},
	"recommendation": {
		"en": "Attach at least the minimum required number of backend servers to all listeners.",
		"zh": "为所有监听至少添加所需最小数量的后端服务器。"
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Listeners"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
