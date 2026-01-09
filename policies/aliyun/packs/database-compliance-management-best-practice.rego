package infraguard.packs.aliyun.database_compliance_management_best_practice

import rego.v1

pack_meta := {
	"id": "database-compliance-management-best-practice",
	"name": {
		"en": "Database Compliance Management Best Practice",
		"zh": "数据库合规管理最佳实践",
	},
	"description": {
		"en": "Best practices for database compliance management",
		"zh": "数据库合规管理最佳实践",
	},
	"rules": [
		"hbase-cluster-expired-check",
		"hbase-cluster-type-check",
		"hbase-cluster-in-vpc",
		# "hbase-cluster-ha-check",
		"hbase-cluster-deletion-protection",
		"mongodb-cluster-expired-check",
		# "mongodb-instance-lock-mode",
		"mongodb-public-access-check",
		"mongodb-instance-release-protection",
		# "mongodb-instance-in-vpc",
		"mongodb-instance-log-audit",
		"polardb-cluster-expired-check",
		# "polardb-public-access-check",
		# "polardb-dbcluster-in-vpc",
		# "polardb-cluster-category-normal",
		"rds-instance-expired-check",
		"rds-public-access-check",
		# "rds-high-availability-category",
		"rds-multi-az-support",
		# "rds-instance-enabled-security-ip-list",
		# "rds-instance-enabled-safety-security-ip",
		"rds-instance-enabled-auditing",
		"rds-instances-in-vpc",
		"rds-instance-enabled-ssl",
		# "rds-instance-enabled-tde",
		# "rds-instance-sql-collector-retention",  # Commented: ROS RDS::DBInstance does not support SQLCollectorRetention property
		# "redis-instance-disable-risk-commands",
		"redis-instance-expired-check",
		# "redis-public-access-check",
		# "redis-architecturetype-cluster-check",
		"redis-instance-release-protection",
		# "redis-instance-in-vpc",
	],
}
