package infraguard.rules.aliyun.redis_instance_backup_log_enabled

import rego.v1

import data.infraguard.helpers

# Rule metadata
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
		"en": "Ensures that log backup is enabled for the Redis instance.",
		"zh": "确保 Redis 实例开启了日志备份。",
		"ja": "Redis インスタンスでログバックアップが有効になっていることを確認します。",
		"de": "Stellt sicher, dass Log-Backup für die Redis-Instanz aktiviert ist.",
		"es": "Garantiza que el backup de log esté habilitado para la instancia Redis.",
		"fr": "Garantit que la sauvegarde de journal est activée pour l'instance Redis.",
		"pt": "Garante que o backup de log esteja habilitado para a instância Redis."
	},
	"reason": {
		"en": "Enabling log backup allows for point-in-time recovery of the database.",
		"zh": "开启日志备份允许对数据库进行按时间点恢复。",
		"ja": "ログバックアップを有効にすることで、データベースのポイントインタイムリカバリが可能になります。",
		"de": "Das Aktivieren von Log-Backup ermöglicht die Point-in-Time-Wiederherstellung der Datenbank.",
		"es": "Habilitar el backup de log permite la recuperación puntual de la base de datos.",
		"fr": "Activer la sauvegarde de journal permet la récupération ponctuelle de la base de données.",
		"pt": "Habilitar backup de log permite recuperação pontual do banco de dados."
	},
	"recommendation": {
		"en": "Enable log backup for the Redis instance.",
		"zh": "为 Redis 实例开启日志备份。",
		"ja": "Redis インスタンスでログバックアップを有効にします。",
		"de": "Aktivieren Sie Log-Backup für die Redis-Instanz.",
		"es": "Habilite backup de log para la instancia Redis.",
		"fr": "Activez la sauvegarde de journal pour l'instance Redis.",
		"pt": "Habilite backup de log para a instância Redis."
	},
	"resource_types": ["ALIYUN::Redis::DBInstance"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::Redis::DBInstance")

	# Conceptual check
	not helpers.get_property(resource, "AppendOnly", "no") == "yes"
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AppendOnly"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
