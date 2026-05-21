package infraguard.rules.terraform.redis_instance_backup_log_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-instance-backup-log-enabled",
	"severity": "medium",
	"name": {
		"en": "Redis Instance Backup Log Enabled",
		"zh": "Redis 实例开启日志备份",
		"ja": "Redis インスタンスでログバックアップが有効",
		"de": "Redis-Instanz Log-Backup aktiviert",
		"es": "Backup de Log de Instancia Redis Habilitado",
		"fr": "Sauvegarde de Journal d'Instance Redis Activée",
		"pt": "Backup de Log de Instância Redis Habilitado"
	},
	"description": {
		"en": "Ensures that backup is configured for the Redis instance.",
		"zh": "确保 Redis 实例配置了备份。",
		"ja": "Redis インスタンスでバックアップが設定されていることを確認します。",
		"de": "Stellt sicher, dass Backup für die Redis-Instanz konfiguriert ist.",
		"es": "Garantiza que el backup esté configurado para la instancia Redis.",
		"fr": "Garantit que la sauvegarde est configurée pour l'instance Redis.",
		"pt": "Garante que o backup esteja configurado para a instância Redis."
	},
	"reason": {
		"en": "Enabling backup allows for point-in-time recovery of the database.",
		"zh": "开启备份允许对数据库进行按时间点恢复。",
		"ja": "バックアップを有効にすることで、データベースのポイントインタイムリカバリが可能になります。",
		"de": "Das Aktivieren von Backup ermöglicht die Point-in-Time-Wiederherstellung der Datenbank.",
		"es": "Habilitar el backup permite la recuperación puntual de la base de datos.",
		"fr": "Activer la sauvegarde permet la récupération ponctuelle de la base de données.",
		"pt": "Habilitar backup permite recuperação pontual do banco de dados."
	},
	"recommendation": {
		"en": "Configure backup_period for the Redis instance.",
		"zh": "为 Redis 实例配置 backup_period。",
		"ja": "Redis インスタンスに backup_period を設定します。",
		"de": "Konfigurieren Sie backup_period für die Redis-Instanz.",
		"es": "Configure backup_period para la instancia Redis.",
		"fr": "Configurez backup_period pour l'instance Redis.",
		"pt": "Configure backup_period para a instância Redis."
	},
	"resource_types": ["alicloud_kvstore_instance"],
	"iac_type": "terraform"
}

is_backup_configured(resource) if {
	backup_period := tf.get_attribute(resource, "backup_period", "")
	not tf.is_unknown(backup_period)
	backup_period != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	not is_backup_configured(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_kvstore_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
