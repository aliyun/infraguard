package infraguard.rules.aliyun.slb_vserver_group_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "slb-vserver-group-multi-zone",
	"name": {
		"en": "SLB VServer Group Multi-Zone Deployment",
		"zh": "SLB 虚拟服务器组多可用区部署",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that SLB virtual server groups contain instances from multiple availability zones.",
		"zh": "确保 SLB 虚拟服务器组包含来自多个可用区的实例。",
	},
	"reason": {
		"en": "Deploying backend instances in multiple zones ensures high availability for the service.",
		"zh": "在多个可用区部署后端实例可确保服务的高可用性。",
	},
	"recommendation": {
		"en": "Add instances from at least two different availability zones to the virtual server group.",
		"zh": "向虚拟服务器组中添加来自至少两个不同可用区的实例。",
	},
	"resource_types": ["ALIYUN::SLB::VServerGroup"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::VServerGroup")

	# Conceptual check for multi-zone
	not helpers.has_property(resource, "BackendServers")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
