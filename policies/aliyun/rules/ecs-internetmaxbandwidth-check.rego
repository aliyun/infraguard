package infraguard.rules.aliyun.ecs_internetmaxbandwidth_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ecs-internetmaxbandwidth-check",
	"name": {
		"en": "ECS Internet Max Bandwidth Check",
		"zh": "ECS 公网出口带宽检查"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures ECS internet outbound bandwidth does not exceed specified limits.",
		"zh": "确保 ECS 公网出口带宽不超过指定限制。"
	},
	"reason": {
		"en": "High bandwidth settings can lead to unexpected costs and increased attack surface.",
		"zh": "高带宽设置可能导致意外成本增加并扩大攻击面。"
	},
	"recommendation": {
		"en": "Limit the InternetMaxBandwidthOut to a reasonable value (e.g., 100Mbps).",
		"zh": "将 InternetMaxBandwidthOut 限制在合理范围内（例如 100Mbps）。"
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

is_compliant(resource) if {
	bandwidth := helpers.get_property(resource, "InternetMaxBandwidthOut", 1)
	bandwidth <= 100
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "InternetMaxBandwidthOut"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
