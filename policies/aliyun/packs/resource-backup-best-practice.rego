package infraguard.packs.aliyun.resource_backup_best_practice

import rego.v1

pack_meta := {
	"id": "resource-backup-best-practice",
	"name": {
		"en": "Resource Backup Best Practice",
		"zh": "资源备份功能开启最佳实践",
	},
	"description": {
		"en": "Best practices for enabling backup features on cloud resources to ensure data protection and disaster recovery.",
		"zh": "为云资源开启备份功能的最佳实践,确保数据保护和灾难恢复。",
	},
	"rules": [
		# "adb-cluster-log-backup-enabled",
		# "eci-container-group-volumn-mounts",
		# "ecs-instance-backup-enable",
		# "elasticsearch-instance-snapshot-enabled",  # Commented: ROS does not support AutoSnapshot property for ALIYUN::ElasticSearch::Instance
		# "gpdb-has-backup-set",
		# "hologram-instance-remote-backup-enable",
		# "mongodb-instance-backup-log-enabled",  # Commented: ROS does not support ALIYUN::MongoDB::DBInstance resource type
		# "nas-filesystem-enable-backup-plan",
		"oss-bucket-versioning-enabled",
		# "ots-instance-remote-replication",
		# "polardb-cluster-log-backup-retention",  # ROS does not support LogBackupRetentionPeriod property
		# "polardb-cluster-level-two-backup-retention",
		"rds-instance-enabled-log-backup",
		"redis-instance-backup-log-enabled",
	],
}
