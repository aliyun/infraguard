package infraguard.rules.aliyun.rds_instance_enabled_log_backup

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rds-instance-enabled-log-backup",
	"name": {
		"en": "RDS Instance Log Backup Enabled",
		"zh": "RDS 实例开启日志备份"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures RDS instances have log backup enabled.",
		"zh": "确保 RDS 实例开启了日志备份。"
	},
	"reason": {
		"en": "Log backups are essential for point-in-time recovery of the database.",
		"zh": "日志备份对于数据库的增量恢复（Point-in-time recovery）至关重要。"
	},
	"recommendation": {
		"en": "Enable log backup in the RDS backup policy.",
		"zh": "在 RDS 备份策略中开启日志备份。"
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "EnableBackupLog", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EnableBackupLog"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
