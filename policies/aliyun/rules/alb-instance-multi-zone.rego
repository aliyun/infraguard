package infraguard.rules.aliyun.alb_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:alb-instance-multi-zone",
	"name": {
		"en": "ALB Instance Multi-Zone Deployment",
		"zh": "使用多可用区的 ALB 实例",
	},
	"severity": "high",
	"description": {
		"en": "ALB instances should be deployed across multiple availability zones for high availability. If only one zone is selected, a zone failure will affect the ALB instance and business stability.",
		"zh": "ALB 实例为多可用区实例，视为合规。如果只选择了一个可用区，当这个可用区出现故障时，会影响 ALB 实例，进而影响业务稳定性。",
	},
	"reason": {
		"en": "The ALB instance is deployed in only one availability zone, which creates a single point of failure.",
		"zh": "ALB 实例仅部署在一个可用区，存在单点故障风险。",
	},
	"recommendation": {
		"en": "Configure the ALB instance to use at least two availability zones by adding multiple zone mappings in the ZoneMappings property.",
		"zh": "通过在 ZoneMappings 属性中添加多个可用区映射，将 ALB 实例配置为使用至少两个可用区。",
	},
	"resource_types": ["ALIYUN::ALB::LoadBalancer"],
}

# Check if ALB is multi-zone
is_multi_zone(resource) if {
	count(object.get(resource.Properties, "ZoneMappings", [])) >= 2
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::LoadBalancer")
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ZoneMappings"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
