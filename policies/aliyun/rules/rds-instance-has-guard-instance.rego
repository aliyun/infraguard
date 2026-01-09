package infraguard.rules.aliyun.rds_instance_has_guard_instance

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:rds-instance-has-guard-instance",
	"name": {
		"en": "RDS Instance Has Guard Instance",
		"zh": "RDS 关键实例配置灾备实例"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures production RDS instances have a corresponding guard (disaster recovery) instance.",
		"zh": "确保生产环境 RDS 实例配置了相应的灾备实例。"
	},
	"reason": {
		"en": "Guard instances provide high availability and data redundancy across regions.",
		"zh": "灾备实例提供跨地域的高可用性和数据冗余。"
	},
	"recommendation": {
		"en": "Configure a guard instance for the primary RDS instance.",
		"zh": "为主要 RDS 实例配置灾备实例。"
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

# Cross-resource check: is there another RDS instance or DR resource linked?
# Simplified for static check: check if it's a high availability category
is_compliant(resource) if {
	cat := helpers.get_property(resource, "Category", "")
	helpers.includes(["HighAvailability", "cluster", "AlwaysOn", "Finance"], cat)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Category"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
