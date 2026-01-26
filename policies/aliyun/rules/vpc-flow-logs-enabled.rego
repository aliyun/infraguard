package infraguard.rules.aliyun.vpc_flow_logs_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "vpc-flow-logs-enabled",
	"name": {
		"en": "VPC Flow Logs Enabled",
		"zh": "VPC 开启流日志"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures VPC flow logs are enabled for monitoring network traffic.",
		"zh": "确保 VPC 开启了流日志，以便监控网络流量。"
	},
	"reason": {
		"en": "Flow logs provide visibility into network traffic patterns and help in security auditing.",
		"zh": "流日志提供了网络流量模式的可见性，有助于安全审计。"
	},
	"recommendation": {
		"en": "Add ALIYUN::VPC::FlowLog resource to enable flow logs for the VPC.",
		"zh": "添加 ALIYUN::VPC::FlowLog 资源以为 VPC 开启流日志。"
	},
	"resource_types": ["ALIYUN::ECS::VPC"],
}

# Cross-resource check: is there a FlowLog resource for this VPC?
has_flow_log(vpc_id) if {
	some name, res in helpers.resources_by_type("ALIYUN::VPC::FlowLog")
	helpers.is_referencing(helpers.get_property(res, "ResourceId", ""), vpc_id)
}

deny contains result if {
	some vpc_id, resource in helpers.resources_by_type("ALIYUN::ECS::VPC")
	not has_flow_log(vpc_id)
	result := {
		"id": rule_meta.id,
		"resource_id": vpc_id,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
