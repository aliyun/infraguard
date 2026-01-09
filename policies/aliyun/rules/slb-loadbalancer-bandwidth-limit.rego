package infraguard.rules.aliyun.slb_loadbalancer_bandwidth_limit

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:slb-loadbalancer-bandwidth-limit",
	"name": {
		"en": "SLB Bandwidth Limit",
		"zh": "SLB 带宽上限核查"
	},
	"severity": "low",
	"description": {
		"en": "Ensures SLB instance bandwidth does not exceed a specified maximum value.",
		"zh": "确保 SLB 实例带宽不超过指定的最高值。"
	},
	"reason": {
		"en": "Controlling SLB bandwidth helps manage network costs.",
		"zh": "控制 SLB 带宽有助于管理网络成本。"
	},
	"recommendation": {
		"en": "Set SLB bandwidth to a reasonable value (e.g., up to 500Mbps).",
		"zh": "将 SLB 带宽设置为合理的值（如不超过 500Mbps）。"
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

is_compliant(resource) if {
	bandwidth := helpers.get_property(resource, "Bandwidth", 1)
	bandwidth <= 500
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Bandwidth"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
