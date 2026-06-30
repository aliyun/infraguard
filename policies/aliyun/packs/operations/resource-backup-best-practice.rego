package infraguard.packs.aliyun.resource_backup_best_practice

import rego.v1

pack_meta := {
	"id": "resource-backup-best-practice",
	"name": {
		"en": "Resource Backup Best Practice",
		"zh": "资源备份功能开启最佳实践",
		"ja": "リソースバックアップのベストプラクティス",
		"de": "Ressourcen-Backup Best Practices",
		"es": "Mejores Prácticas de Respaldo de Recursos",
		"fr": "Meilleures Pratiques de Sauvegarde des Ressources",
		"pt": "Melhores Práticas de Backup de Recursos"
	},
	"description": {
		"en": "Best practices for enabling backup features on cloud resources to ensure data protection and disaster recovery.",
		"zh": "为云资源开启备份功能的最佳实践,确保数据保护和灾难恢复。",
		"ja": "データ保護と災害復旧を確保するために、クラウドリソースでバックアップ機能を有効にするベストプラクティス。",
		"de": "Best Practices zur Aktivierung von Backup-Funktionen für Cloud-Ressourcen, um Datenschutz und Disaster Recovery sicherzustellen.",
		"es": "Mejores prácticas para habilitar funciones de respaldo en recursos en la nube para garantizar la protección de datos y la recuperación ante desastres.",
		"fr": "Meilleures pratiques pour activer les fonctions de sauvegarde sur les ressources cloud afin d'assurer la protection des données et la récupération d'urgence.",
		"pt": "Melhores práticas para habilitar recursos de backup em recursos em nuvem para garantir proteção de dados e recuperação de desastres."
	},
	"rules": [
		# "adb-cluster-log-backup-enabled",
		# "eci-container-group-volumn-mounts",
		# "ecs-instance-backup-enable",
		# "elasticsearch-instance-snapshot-enabled",  # Commented: ROS does not support AutoSnapshot property for ALIYUN::ElasticSearch::Instance,
		# "gpdb-has-backup-set",
		# "hologram-instance-remote-backup-enable",
		# "mongodb-instance-backup-log-enabled",  # Commented: ROS does not support ALIYUN::MongoDB::DBInstance resource type,
		# "nas-filesystem-enable-backup-plan",
		"oss-bucket-versioning-enabled",
		# "ots-instance-remote-replication",
		# "polardb-cluster-level-two-backup-retention",
		# "polardb-cluster-log-backup-retention",  # ROS does not support LogBackupRetentionPeriod property,
		"rds-instance-enabled-log-backup",
		"redis-instance-backup-log-enabled"
	]
}
