package infraguard.rules.aliyun.ecs_instance_type_family_not_deprecated

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ecs-instance-type-family-not-deprecated",
	"name": {
		"en": "ECS Instance Type Not Deprecated",
		"zh": "ECS 弃用规格族预警"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures ECS instances do not use deprecated or legacy instance types.",
		"zh": "确保 ECS 实例未使用已弃用或陈旧的规格类型。"
	},
	"reason": {
		"en": "Legacy instance types may have lower performance and limited future availability.",
		"zh": "陈旧的实例类型可能性能较低，且未来的可用性受限。"
	},
	"recommendation": {
		"en": "Move to newer generation instance types (e.g., g6, c6, r6).",
		"zh": "迁移至新一代实例规格（如 g6, c6, r6）。"
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

deprecated_prefixes := ["ecs.t1.", "ecs.s1.", "ecs.m1.", "ecs.c1.", "ecs.n1."]

is_compliant(resource) if {
	type := helpers.get_property(resource, "InstanceType", "")
	not is_deprecated(type)
}

is_deprecated(type) if {
	some prefix in deprecated_prefixes
	startswith(type, prefix)
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "InstanceType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
