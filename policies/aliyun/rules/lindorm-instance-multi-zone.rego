package infraguard.rules.aliyun.lindorm_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "lindorm-instance-multi-zone",
	"name": {
		"en": "Lindorm Instance Multi-Zone Deployment",
		"zh": "使用多可用区的云原生多模数据库 Lindorm 实例",
	},
	"severity": "medium",
	"description": {
		"en": "Lindorm instances should be configured for multi-zone deployment with at least 4 LindormTable nodes for high availability.",
		"zh": "使用多可用区的云原生多模数据库 Lindorm 实例，视为合规。",
	},
	"reason": {
		"en": "The Lindorm instance does not meet the multi-zone deployment requirements (LindormNum < 4).",
		"zh": "Lindorm 实例不满足多可用区部署要求（LindormNum < 4）。",
	},
	"recommendation": {
		"en": "Configure at least 4 LindormTable nodes by setting LindormNum to 4 or more to enable multi-zone deployment.",
		"zh": "通过将 LindormNum 设置为 4 或更多来配置至少 4 个 LindormTable 节点，以启用多可用区部署。",
	},
	"resource_types": ["ALIYUN::Lindorm::Instance"],
}

# Check if instance is multi-zone (requires LindormNum >= 4)
is_multi_zone(resource) if {
	helpers.has_property(resource, "LindormNum")
	lindorm_num := resource.Properties.LindormNum
	lindorm_num >= 4
}

# Deny rule: Lindorm instances should be multi-zone
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::Lindorm::Instance")
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LindormNum"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
