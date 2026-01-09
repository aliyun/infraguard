package infraguard.rules.aliyun.eip_bandwidth_limit

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:eip-bandwidth-limit",
	"name": {
		"en": "EIP Bandwidth Limit",
		"zh": "EIP 带宽上限核查"
	},
	"severity": "low",
	"description": {
		"en": "Ensures EIP bandwidth does not exceed a specified maximum value.",
		"zh": "确保 EIP 带宽不超过指定的最高值。"
	},
	"reason": {
		"en": "Excessive bandwidth settings can lead to higher than expected costs.",
		"zh": "过高的带宽设置可能导致超出预期的成本。"
	},
	"recommendation": {
		"en": "Set EIP bandwidth to a reasonable value (e.g., up to 100Mbps).",
		"zh": "将 EIP 带宽设置为合理的值（如不超过 100Mbps）。"
	},
	"resource_types": ["ALIYUN::VPC::EIP"],
}

is_compliant(resource) if {
	bandwidth := helpers.get_property(resource, "Bandwidth", 5)
	bandwidth <= 100
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::EIP")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Bandwidth"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
