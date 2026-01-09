package infraguard.rules.aliyun.slb_all_listener_servers_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:slb-all-listener-servers-multi-zone",
	"name": {
		"en": "SLB Multi-Zone with Multi-Zone Backend Servers",
		"zh": "使用多可用区 SLB 实例并为服务器组配置多个可用区资源",
	},
	"severity": "high",
	"description": {
		"en": "SLB instances should be multi-zone, and all server groups used by listeners should have resources added from multiple zones.",
		"zh": "SLB 实例为多可用区，并且 SLB 实例下所有监听使用的服务器组中添加了多个可用区的资源，视为合规。",
	},
	"reason": {
		"en": "Single zone deployment or single zone backend servers lack high availability and may lead to service interruption during zone failure.",
		"zh": "单可用区部署或后端服务器仅位于单个可用区缺乏高可用性，可能在可用区故障时导致服务中断。",
	},
	"recommendation": {
		"en": "Configure SLB instances with master and slave zones, and ensure backend server groups include instances from different availability zones.",
		"zh": "为 SLB 实例配置主备可用区，并确保后端服务器组包含来自不同可用区的实例。",
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

# Check if SLB instance has slave zone configured
is_multi_zone(resource) if {
	helpers.has_property(resource, "SlaveZoneId")
	slave_zone := resource.Properties.SlaveZoneId
	slave_zone != ""
}

# Deny rule: SLB instances should be multi-zone
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SlaveZoneId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
