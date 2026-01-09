package infraguard.rules.aliyun.slb_instance_default_server_group_multi_zone

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:slb-instance-default-server-group-multi-zone",
	"name": {
		"en": "SLB Default Server Group Multi-Zone",
		"zh": "SLB 负载均衡默认服务器组添加多个可用区资源"
	},
	"severity": "medium",
	"description": {
		"en": "The default server group of SLB instances should have resources distributed across multiple availability zones.",
		"zh": "SLB 负载均衡的默认服务器组挂载资源分布在多个可用区，视为合规。默认服务器组无挂载任何资源时不适用本规则，视为不适用。"
	},
	"reason": {
		"en": "Single-zone backend servers create a single point of failure and reduce availability.",
		"zh": "单可用区后端服务器创建单点故障并降低可用性。"
	},
	"recommendation": {
		"en": "Distribute backend servers across multiple availability zones for high availability.",
		"zh": "为实现高可用性，将后端服务器分布在多个可用区。"
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

has_multi_zone_servers(resource) if {
	backend_servers := helpers.get_property(resource, "BackendServers", [])

	# Check if servers are in different zones
	count(backend_servers) > 1
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	backend_servers := helpers.get_property(resource, "BackendServers", [])
	count(backend_servers) > 0
	not has_multi_zone_servers(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "BackendServers"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
