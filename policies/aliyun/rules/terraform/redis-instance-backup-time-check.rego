package infraguard.rules.terraform.redis_instance_backup_time_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-instance-backup-time-check",
	"severity": "low",
	"name": {
		"en": "Redis Instance Backup Window Check",
		"zh": "Redis 实例备份时间检测",
		"ja": "Redis インスタンスのバックアップウィンドウチェック",
		"de": "Redis-Instanz Backup-Fenster-Prüfung",
		"es": "Verificación de Ventana de Respaldo de Instancia Redis",
		"fr": "Vérification de la Fenêtre de Sauvegarde de l'Instance Redis",
		"pt": "Verificação de Janela de Backup de Instância Redis"
	},
	"description": {
		"en": "Ensures that the Redis instance has a backup window configured.",
		"zh": "确保 Redis 实例配置了备份时间段。",
		"ja": "Redis インスタンスにバックアップウィンドウが設定されていることを確認します。",
		"de": "Stellt sicher, dass die Redis-Instanz ein Backup-Fenster konfiguriert hat.",
		"es": "Garantiza que la instancia Redis tenga configurada una ventana de respaldo.",
		"fr": "Garantit que l'instance Redis a une fenêtre de sauvegarde configurée.",
		"pt": "Garante que a instância Redis tenha uma janela de backup configurada."
	},
	"reason": {
		"en": "Configuring a backup window ensures that backups are taken during off-peak hours.",
		"zh": "配置备份时间段可确保在非高峰时段进行备份。",
		"ja": "バックアップウィンドウを設定することで、オフピーク時間帯にバックアップが実行されることを確保します。",
		"de": "Die Konfiguration eines Backup-Fensters stellt sicher, dass Backups während der Nebenzeiten durchgeführt werden.",
		"es": "Configurar una ventana de respaldo garantiza que los respaldos se realicen durante las horas de menor actividad.",
		"fr": "La configuration d'une fenêtre de sauvegarde garantit que les sauvegardes sont effectuées pendant les heures creuses.",
		"pt": "Configurar uma janela de backup garante que os backups sejam feitos durante as horas de menor movimento."
	},
	"recommendation": {
		"en": "Configure backup_time for the Redis instance.",
		"zh": "为 Redis 实例配置 backup_time。",
		"ja": "Redis インスタンスに backup_time を設定します。",
		"de": "Konfigurieren Sie backup_time für die Redis-Instanz.",
		"es": "Configure backup_time para la instancia Redis.",
		"fr": "Configurez backup_time pour l'instance Redis.",
		"pt": "Configure backup_time para a instância Redis."
	},
	"resource_types": ["alicloud_kvstore_instance"],
	"iac_type": "terraform"
}

is_backup_time_set(resource) if {
	backup_time := tf.get_attribute(resource, "backup_time", "")
	not tf.is_unknown(backup_time)
	backup_time != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	not is_backup_time_set(resource)
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
