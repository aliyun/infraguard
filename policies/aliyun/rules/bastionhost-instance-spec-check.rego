package infraguard.rules.aliyun.bastionhost_instance_spec_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "bastionhost-instance-spec-check",
	"name": {
		"en": "BastionHost Instance Multi-Zone Spec Check",
		"zh": "使用多可用区部署的堡垒机版本",
	},
	"severity": "medium",
	"description": {
		"en": "The BastionHost instance should use the Enterprise version which supports multi-zone deployment.",
		"zh": "使用多可用区部署的企业双擎或者国密版堡垒机，保障稳定性，视为合规。",
	},
	"reason": {
		"en": "The BastionHost instance is using the Basic version which implies single-zone deployment.",
		"zh": "堡垒机实例使用的是不支持多可用区部署的基础版。",
	},
	"recommendation": {
		"en": "Upgrade the BastionHost instance to the Enterprise version.",
		"zh": "将堡垒机实例升级到企业版。",
	},
	"resource_types": ["ALIYUN::BastionHost::Instance"],
}

# Check if instance is Enterprise version
is_enterprise(resource) if {
	resource.Properties.Version == "Enterprise"
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_enterprise(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Version"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
