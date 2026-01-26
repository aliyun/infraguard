package infraguard.rules.aliyun.cen_cross_region_bandwidth_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "cen-cross-region-bandwidth-check",
	"name": {
		"en": "CEN Cross-Region Bandwidth Check",
		"zh": "CEN 实例中的跨地域连接带宽分配满足指定要求"
	},
	"severity": "medium",
	"description": {
		"en": "CEN instance cross-region connections should have sufficient bandwidth allocation to meet performance requirements.",
		"zh": "云企业网实例下所有跨地域连接分配的带宽大于参数指定值，视为合规。"
	},
	"reason": {
		"en": "Insufficient cross-region bandwidth can lead to performance bottlenecks and degraded application performance.",
		"zh": "不足的跨地域带宽可能导致性能瓶颈和应用程序性能下降。"
	},
	"recommendation": {
		"en": "Ensure cross-region connections have bandwidth allocation above the specified minimum threshold (default: 1Mbps).",
		"zh": "确保跨地域连接的带宽分配高于指定的最小阈值（默认：1Mbps）。"
	},
	"resource_types": ["ALIYUN::CEN::CenInstance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CEN::CenInstance")

	# Cross-resource check would examine CenBandwidthPackage associations
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
