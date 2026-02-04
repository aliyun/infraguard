package infraguard.packs.aliyun.polardb_application_best_practice

import rego.v1

pack_meta := {
	"id": "polardb-application-best-practice",
	"name": {
		"en": "PolarDB Application Best Practice",
		"zh": "PolarDB 应用最佳实践",
		"ja": "PolarDB アプリケーションのベストプラクティス",
		"de": "PolarDB-Anwendung Best Practices",
		"es": "Mejores Prácticas de Aplicación PolarDB",
		"fr": "Meilleures Pratiques d'Application PolarDB",
		"pt": "Melhores Práticas de Aplicação PolarDB"
	},
	"description": {
		"en": "Best practices for PolarDB cluster configuration, covering security, backup, version management, and operational settings.",
		"zh": "PolarDB 集群配置最佳实践,涵盖安全、备份、版本管理和运维设置。",
		"ja": "セキュリティ、バックアップ、バージョン管理、運用設定をカバーする PolarDB クラスタ設定のベストプラクティス。",
		"de": "Best Practices für die PolarDB-Cluster-Konfiguration, einschließlich Sicherheit, Backup, Versionsverwaltung und Betriebseinstellungen.",
		"es": "Mejores prácticas para la configuración de clústeres PolarDB, que cubre seguridad, respaldo, gestión de versiones y configuraciones operativas.",
		"fr": "Meilleures pratiques pour la configuration des clusters PolarDB, couvrant la sécurité, la sauvegarde, la gestion des versions et les configurations opérationnelles.",
		"pt": "Melhores práticas para configuração de cluster PolarDB, cobrindo segurança, backup, gerenciamento de versão e configurações operacionais."
	},
	"rules": [
		# "polardb-cluster-category-normal",
		# "polardb-cluster-default-time-zone-not-system",
		"polardb-cluster-delete-protection-enabled",
		# "polardb-cluster-enabled-auditing",  # ROS does not support SQLCollectorStatus property,
		"polardb-cluster-expired-check",
		# "polardb-cluster-level-two-backup-retention",
		# "polardb-cluster-log-backup-retention",  # ROS does not support LogBackupRetentionPeriod property,
		"polardb-cluster-maintain-time-check",
		"polardb-public-and-any-ip-access-check",
		# "polardb-revision-version-used-check"
	]
}
