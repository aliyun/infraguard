package infraguard.packs.aliyun.database_compliance_management_best_practice

import rego.v1

pack_meta := {
	"id": "database-compliance-management-best-practice",
	"name": {
		"en": "Database Compliance Management Best Practice",
		"zh": "数据库合规管理最佳实践",
		"ja": "データベースコンプライアンス管理のベストプラクティス",
		"de": "Datenbank-Compliance-Management Best Practices",
		"es": "Mejores Prácticas de Gestión de Cumplimiento de Bases de Datos",
		"fr": "Meilleures Pratiques de Gestion de la Conformité des Bases de Données",
		"pt": "Melhores Práticas de Gestão de Conformidade de Banco de Dados"
	},
	"description": {
		"en": "Best practices for database compliance management",
		"zh": "数据库合规管理最佳实践",
		"ja": "データベースコンプライアンス管理のベストプラクティス",
		"de": "Best Practices für das Datenbank-Compliance-Management",
		"es": "Mejores prácticas para la gestión de cumplimiento de bases de datos",
		"fr": "Meilleures pratiques pour la gestion de la conformité des bases de données",
		"pt": "Melhores práticas para gestão de conformidade de banco de dados"
	},
	"rules": [
		"hbase-cluster-deletion-protection",
		"hbase-cluster-expired-check",
		# "hbase-cluster-ha-check",
		"hbase-cluster-in-vpc",
		"hbase-cluster-type-check",
		"mongodb-cluster-expired-check",
		# "mongodb-instance-in-vpc",
		# "mongodb-instance-lock-mode",
		"mongodb-instance-log-audit",
		"mongodb-instance-release-protection",
		"mongodb-public-access-check",
		# "polardb-cluster-category-normal",
		"polardb-cluster-expired-check",
		# "polardb-dbcluster-in-vpc",
		# "polardb-public-access-check",
		# "rds-high-availability-category",
		"rds-instance-enabled-auditing",
		# "rds-instance-enabled-safety-security-ip",
		# "rds-instance-enabled-security-ip-list",
		"rds-instance-enabled-ssl",
		# "rds-instance-enabled-tde",
		"rds-instance-expired-check",
		# "rds-instance-sql-collector-retention",  # Commented: ROS RDS::DBInstance does not support SQLCollectorRetention property,
		"rds-instances-in-vpc",
		"rds-multi-az-support",
		"rds-public-access-check",
		# "redis-architecturetype-cluster-check",
		# "redis-instance-disable-risk-commands",
		"redis-instance-expired-check",
		# "redis-instance-in-vpc",
		"redis-instance-release-protection",
		# "redis-public-access-check"
	]
}
