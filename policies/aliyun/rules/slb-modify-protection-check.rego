package infraguard.rules.aliyun.slb_modify_protection_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:slb-modify-protection-check",
	"name": {
		"en": "SLB Modification Protection Enabled",
		"zh": "SLB 实例开启配置修改保护",
	},
	"severity": "low",
	"description": {
		"en": "Ensures that SLB instances have modification protection enabled.",
		"zh": "确保 SLB 实例开启了配置修改保护。",
	},
	"reason": {
		"en": "If modification protection is not enabled, the SLB configuration may be modified accidentally, causing service issues.",
		"zh": "如果未开启配置修改保护，SLB 配置可能会被意外修改，导致服务异常。",
	},
	"recommendation": {
		"en": "Enable modification protection for the SLB instance.",
		"zh": "为 SLB 实例开启配置修改保护功能。",
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

is_compliant(resource) if {
	helpers.get_property(resource, "ModificationProtectionStatus", "") == "ConsoleProtection"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ModificationProtectionStatus"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
