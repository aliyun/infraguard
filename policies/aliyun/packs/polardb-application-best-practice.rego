package infraguard.packs.aliyun.polardb_application_best_practice

import rego.v1

pack_meta := {
	"id": "polardb-application-best-practice",
	"name": {
		"en": "PolarDB Application Best Practice",
		"zh": "PolarDB 应用最佳实践",
	},
	"description": {
		"en": "Best practices for PolarDB cluster configuration, covering security, backup, version management, and operational settings.",
		"zh": "PolarDB 集群配置最佳实践,涵盖安全、备份、版本管理和运维设置。",
	},
	"rules": [
		# "polardb-revision-version-used-check",
		"polardb-cluster-expired-check",
		"polardb-public-and-any-ip-access-check",
		# "polardb-cluster-default-time-zone-not-system",
		# "polardb-cluster-enabled-auditing",  # ROS does not support SQLCollectorStatus property
		"polardb-cluster-maintain-time-check",
		"polardb-cluster-delete-protection-enabled",
		# "polardb-cluster-log-backup-retention",  # ROS does not support LogBackupRetentionPeriod property
		# "polardb-cluster-category-normal",
		# "polardb-cluster-level-two-backup-retention",
	],
}
