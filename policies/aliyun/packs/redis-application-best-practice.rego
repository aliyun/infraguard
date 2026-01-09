package infraguard.packs.aliyun.redis_application_best_practice

import rego.v1

pack_meta := {
	"id": "redis-application-best-practice",
	"name": {
		"en": "Redis Application Best Practice",
		"zh": "Redis 应用最佳实践",
	},
	"description": {
		"en": "Best practices for Redis instance configuration, covering high availability, security, backup, performance, and operational settings.",
		"zh": "Redis 实例配置最佳实践,涵盖高可用、安全、备份、性能和运维设置。",
	},
	"rules": [
		"redis-instance-multi-zone",
		# "redis-instance-double-node-type",
		# "redis-instance-disable-risk-commands",
		"redis-public-and-any-ip-access-check",
		"redis-instance-expired-check",
		# "redis-instance-audit-log-retention",
		"redis-instance-enabled-byok-tde",
		"redis-instance-enabled-ssl",
		# "redis-instance-upgrade-latest-version",
		"redis-instance-release-protection",
		"redis-instance-backup-time-check",
		# "redis-instance-enabled-audit-log",  # Commented: ROS ALIYUN::REDIS::Instance does not support AuditLogConfig property
		# "redis-min-qps-limit",
		# "redis-min-bandwidth-limit",
		# "redis-min-capacity-limit",
		"redis-instance-backup-log-enabled",
	],
}
