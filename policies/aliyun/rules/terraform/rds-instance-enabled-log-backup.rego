package infraguard.rules.terraform.rds_instance_enabled_log_backup

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-instance-enabled-log-backup",
	"severity": "medium",
	"name": {
		"en": "RDS Instance Log Backup Enabled",
		"zh": "RDS 实例开启日志备份",
		"ja": "RDS インスタンスでログバックアップが有効",
		"de": "RDS-Instanz Log-Backup aktiviert",
		"es": "Backup de Log de Instancia RDS Habilitado",
		"fr": "Sauvegarde de Journal d'Instance RDS Activée",
		"pt": "Backup de Log de Instância RDS Habilitado"
	},
	"description": {
		"en": "Ensures RDS instances have log backup enabled.",
		"zh": "确保 RDS 实例开启了日志备份。",
		"ja": "RDS インスタンスでログバックアップが有効になっていることを確認します。",
		"de": "Stellt sicher, dass RDS-Instanzen Log-Backup aktiviert haben.",
		"es": "Garantiza que las instancias RDS tengan backup de log habilitado.",
		"fr": "Garantit que les instances RDS ont la sauvegarde de journal activée.",
		"pt": "Garante que as instâncias RDS tenham backup de log habilitado."
	},
	"reason": {
		"en": "Log backups are essential for point-in-time recovery of the database.",
		"zh": "日志备份对于数据库的增量恢复（Point-in-time recovery）至关重要。",
		"ja": "ログバックアップは、データベースのポイントインタイムリカバリに不可欠です。",
		"de": "Log-Backups sind für die Point-in-Time-Wiederherstellung der Datenbank unerlässlich.",
		"es": "Los backups de log son esenciales para la recuperación puntual de la base de datos.",
		"fr": "Les sauvegardes de journal sont essentielles pour la récupération ponctuelle de la base de données.",
		"pt": "Backups de log são essenciais para recuperação pontual do banco de dados."
	},
	"recommendation": {
		"en": "Set enable_backup_log to true in the RDS backup policy.",
		"zh": "在 RDS 备份策略中将 enable_backup_log 设置为 true。",
		"ja": "RDS バックアップポリシーで enable_backup_log を true に設定します。",
		"de": "Setzen Sie enable_backup_log in der RDS-Backup-Richtlinie auf true.",
		"es": "Establezca enable_backup_log en true en la política de backup RDS.",
		"fr": "Définissez enable_backup_log sur true dans la politique de sauvegarde RDS.",
		"pt": "Defina enable_backup_log como true na política de backup RDS."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	val := tf.get_attribute(resource, "enable_backup_log", false)
	val != true
	val != 1
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
