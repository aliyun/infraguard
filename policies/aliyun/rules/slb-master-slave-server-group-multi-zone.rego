package infraguard.rules.aliyun.slb_master_slave_server_group_multi_zone

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-master-slave-server-group-multi-zone",
	"name": {
		"en": "SLB Master-Slave Server Group Multi-Zone",
		"zh": "SLB 负载均衡主备服务器组添加多个可用区资源"
	},
	"severity": "medium",
	"description": {
		"en": "The master-slave server group of SLB instances should have resources distributed across multiple availability zones.",
		"zh": "SLB 负载均衡的主备服务器组挂载资源分布在多个可用区，视为合规。主备服务器组无挂载任何资源时不适用本规则，视为不适用。"
	},
	"reason": {
		"en": "Single-zone master-slave servers create a single point of failure and reduce availability.",
		"zh": "单可用区主备服务器创建单点故障并降低可用性。"
	},
	"recommendation": {
		"en": "Distribute master and slave servers across different availability zones.",
		"zh": "将主服务器和从服务器分布在不同的可用区。"
	},
	"resource_types": ["ALIYUN::SLB::MasterSlaveServerGroup"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::MasterSlaveServerGroup")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
