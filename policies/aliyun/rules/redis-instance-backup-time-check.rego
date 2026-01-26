package infraguard.rules.aliyun.redis_instance_backup_time_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "redis-instance-backup-time-check",
	"name": {
		"en": "Redis Instance Backup Window Check",
		"zh": "Redis 实例备份时间检测",
	},
	"severity": "low",
	"description": {
		"en": "Ensures that the Redis instance has a backup window configured.",
		"zh": "确保 Redis 实例配置了备份时间段。",
	},
	"reason": {
		"en": "Configuring a backup window ensures that backups are taken during off-peak hours.",
		"zh": "配置备份时间段可确保在非高峰时段进行备份。",
	},
	"recommendation": {
		"en": "Configure a backup window for the Redis instance.",
		"zh": "为 Redis 实例配置备份时间段。",
	},
	"resource_types": ["ALIYUN::Redis::DBInstance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::Redis::DBInstance")
	not helpers.has_property(resource, "BackupTime")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "BackupTime"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
