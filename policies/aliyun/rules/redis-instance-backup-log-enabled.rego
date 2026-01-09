package infraguard.rules.aliyun.redis_instance_backup_log_enabled

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:redis-instance-backup-log-enabled",
	"name": {
		"en": "Redis Instance Backup Log Enabled",
		"zh": "Redis 实例开启日志备份",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that log backup is enabled for the Redis instance.",
		"zh": "确保 Redis 实例开启了日志备份。",
	},
	"reason": {
		"en": "Enabling log backup allows for point-in-time recovery of the database.",
		"zh": "开启日志备份允许对数据库进行按时间点恢复。",
	},
	"recommendation": {
		"en": "Enable log backup for the Redis instance.",
		"zh": "为 Redis 实例开启日志备份。",
	},
	"resource_types": ["ALIYUN::Redis::DBInstance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::Redis::DBInstance")

	# Conceptual check
	not helpers.get_property(resource, "AppendOnly", "no") == "yes"
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AppendOnly"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
