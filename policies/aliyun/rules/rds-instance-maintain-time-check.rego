package infraguard.rules.aliyun.rds_instance_maintain_time_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:rds-instance-maintain-time-check",
	"name": {
		"en": "RDS Instance Maintenance Window Check",
		"zh": "RDS 实例维护时间检测",
	},
	"severity": "low",
	"description": {
		"en": "Ensures that the RDS instance has a maintenance window configured.",
		"zh": "确保 RDS 实例配置了维护时间段。",
	},
	"reason": {
		"en": "Configuring a maintenance window allows for planned maintenance during off-peak hours.",
		"zh": "配置维护时间段允许在非高峰时段进行计划内维护。",
	},
	"recommendation": {
		"en": "Configure a maintenance window for the RDS instance.",
		"zh": "为 RDS 实例配置维护时间段。",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not helpers.has_property(resource, "MaintainTime")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "MaintainTime"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
