package infraguard.rules.aliyun.alb_all_listenter_has_server

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:alb-all-listenter-has-server",
	"name": {
		"en": "ALB Listener Has Backend Server",
		"zh": "ALB 监听绑定后端服务器"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures all ALB listeners are associated with a non-empty server group.",
		"zh": "确保所有 ALB 监听均关联了非空的服务器组。"
	},
	"reason": {
		"en": "A listener without backend servers cannot handle any traffic, leading to service unavailability.",
		"zh": "未绑定后端服务器的监听无法处理任何流量，会导致服务不可用。"
	},
	"recommendation": {
		"en": "Associate the listener with a server group that contains healthy backend servers.",
		"zh": "将监听关联到包含健康后端服务器的服务器组。"
	},
	"resource_types": ["ALIYUN::ALB::Listener"],
}

is_compliant(resource) if {
	# Check if DefaultActions contains ForwardGroup with ServerGroupTuples
	default_actions := helpers.get_property(resource, "DefaultActions", [])
	some action in default_actions
	action.Type == "ForwardGroup"
	forward_group_config := action.ForwardGroupConfig
	server_group_tuples := forward_group_config.ServerGroupTuples
	count(server_group_tuples) > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DefaultActions"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
