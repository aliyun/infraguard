package infraguard.rules.aliyun.slb_instance_spec_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:slb-instance-spec-check",
	"name": {
		"en": "SLB Instance Specification Check",
		"zh": "SLB 实例规格满足要求"
	},
	"severity": "medium",
	"description": {
		"en": "SLB instance specifications should meet the required performance criteria based on the specified list.",
		"zh": "SLB 实例规格在指定的规格列表中，视为合规。"
	},
	"reason": {
		"en": "Using low-specification SLB instances may not meet performance requirements and could lead to bottlenecks.",
		"zh": "使用低规格 SLB 实例可能无法满足性能要求，可能导致瓶颈。"
	},
	"recommendation": {
		"en": "Use SLB instances with specifications that meet your performance requirements.",
		"zh": "使用满足性能要求的 SLB 实例规格。"
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

# Allowed specifications (example)
allowed_specs := {
	"slb.s3.small",
	"slb.s3.medium",
	"slb.s3.large",
	"slb.s3.xlarge",
	"slb.s3.xxlarge",
}

is_valid_spec(resource) if {
	spec := helpers.get_property(resource, "LoadBalancerSpec", "")
	spec == ""
}

is_valid_spec(resource) if {
	spec := helpers.get_property(resource, "LoadBalancerSpec", "")
	spec in allowed_specs
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_valid_spec(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LoadBalancerSpec"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
