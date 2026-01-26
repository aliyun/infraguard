package infraguard.rules.aliyun.rds_instance_enabled_auditing

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rds-instance-enabled-auditing",
	"name": {
		"en": "RDS Instance Auditing Enabled",
		"zh": "RDS 实例开启 SQL 审计"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures RDS instances have SQL auditing enabled.",
		"zh": "确保 RDS 实例开启了 SQL 审计。"
	},
	"reason": {
		"en": "SQL auditing helps track database activities and investigate security incidents.",
		"zh": "SQL 审计有助于跟踪数据库活动并调查安全事件。"
	},
	"recommendation": {
		"en": "Enable SQL Collector for the RDS instance.",
		"zh": "为 RDS 实例开启 SQL 审计（SQL Collector）。"
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

is_compliant(resource) if {
	helpers.get_property(resource, "SQLCollectorStatus", "Disabled") == "Enable"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SQLCollectorStatus"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
