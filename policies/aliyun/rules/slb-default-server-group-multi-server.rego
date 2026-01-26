package infraguard.rules.aliyun.slb_default_server_group_multi_server

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-default-server-group-multi-server",
	"name": {
		"en": "SLB Default Server Group Has Multiple Servers",
		"zh": "SLB 实例默认服务器组包含至少两台服务器"
	},
	"severity": "medium",
	"description": {
		"en": "The default server group of SLB instances should have at least two servers to avoid single point of failure.",
		"zh": "SLB 实例的默认服务器组至少添加两台服务器，视为合规。"
	},
	"reason": {
		"en": "A single backend server creates a single point of failure and reduces availability.",
		"zh": "单一后端服务器创建单点故障并降低可用性。"
	},
	"recommendation": {
		"en": "Add at least two servers to the default server group for high availability.",
		"zh": "为实现高可用性，在默认服务器组中至少添加两台服务器。"
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

has_multiple_servers(resource) if {
	backend_servers := helpers.get_property(resource, "BackendServers", [])
	count(backend_servers) >= 2
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not has_multiple_servers(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "BackendServers"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
