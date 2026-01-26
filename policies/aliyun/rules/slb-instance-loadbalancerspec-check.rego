package infraguard.rules.aliyun.slb_instance_loadbalancerspec_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-instance-loadbalancerspec-check",
	"name": {
		"en": "SLB Instance Spec Check",
		"zh": "SLB 规格合规性检查"
	},
	"severity": "low",
	"description": {
		"en": "Ensures SLB instances use approved performance specifications.",
		"zh": "确保 SLB 实例使用批准的性能规格。"
	},
	"reason": {
		"en": "Using specific specs helps in cost management and performance standardization.",
		"zh": "使用特定规格有助于成本管理和性能标准化。"
	},
	"recommendation": {
		"en": "Use a spec from the approved list (e.g., slb.s1.small).",
		"zh": "使用批准列表中的规格（如 slb.s1.small）。"
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

allowed_specs := ["slb.s1.small", "slb.s2.small", "slb.s3.small"]

is_compliant(resource) if {
	spec := helpers.get_property(resource, "LoadBalancerSpec", "")
	helpers.includes(allowed_specs, spec)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LoadBalancerSpec"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
