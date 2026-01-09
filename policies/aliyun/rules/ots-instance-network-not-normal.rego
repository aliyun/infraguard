package infraguard.rules.aliyun.ots_instance_network_not_normal

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:ots-instance-network-not-normal",
	"name": {
		"en": "OTS Restricted Network Type",
		"zh": "OTS 实例限制网络类型"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Table Store (OTS) instances do not use the 'Normal' (unrestricted) network type.",
		"zh": "确保表格存储（OTS）实例未使用 'Normal'（无限制）网络类型。"
	},
	"reason": {
		"en": "Using VPC or bound-VPC network types provides better isolation than the Normal type.",
		"zh": "使用 VPC 或绑定 VPC 网络类型比 Normal 类型提供更好的隔离性。"
	},
	"recommendation": {
		"en": "Set Network to 'Vpc' or 'VpcAndConsole' for the OTS instance.",
		"zh": "为 OTS 实例将 Network 设置为 'Vpc' 或 'VpcAndConsole'。"
	},
	"resource_types": ["ALIYUN::OTS::Instance"],
}

is_compliant(resource) if {
	net := helpers.get_property(resource, "Network", "Normal")
	net != "Normal"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OTS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Network"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
