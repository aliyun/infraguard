package infraguard.rules.aliyun.pai_eas_instances_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:pai-eas-instances-multi-zone",
	"name": {
		"en": "PAI EAS Instance Multi-Zone Deployment",
		"zh": "PAI EAS 实例多可用区部署",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that PAI EAS instances are deployed across multiple zones for high availability.",
		"zh": "确保 PAI EAS 实例部署在多个可用区以实现高可用性。",
	},
	"reason": {
		"en": "Multi-zone deployment ensures service availability during availability zone failures.",
		"zh": "多可用区部署可确保在可用区故障期间的服务可用性。",
	},
	"recommendation": {
		"en": "Deploy PAI EAS instances in at least two different availability zones.",
		"zh": "在至少两个不同的可用区中部署 PAI EAS 实例。",
	},
	"resource_types": ["ALIYUN::PAI::Service"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::PAI::Service")

	# Conceptual check for multi-zone deployment
	not helpers.has_property(resource, "MultiAZ") # Simplified
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
