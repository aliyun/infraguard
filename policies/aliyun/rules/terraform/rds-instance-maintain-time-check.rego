package infraguard.rules.terraform.rds_instance_maintain_time_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-instance-maintain-time-check",
	"severity": "low",
	"name": {
		"en": "RDS Instance Maintenance Window Check",
		"zh": "RDS 实例维护时间检测",
		"ja": "RDS インスタンスのメンテナンスウィンドウチェック",
		"de": "RDS-Instanz Wartungsfenster-Prüfung",
		"es": "Verificación de Ventana de Mantenimiento de Instancia RDS",
		"fr": "Vérification de la Fenêtre de Maintenance de l'Instance RDS",
		"pt": "Verificação de Janela de Manutenção de Instância RDS"
	},
	"description": {
		"en": "Ensures that the RDS instance has a maintenance window configured.",
		"zh": "确保 RDS 实例配置了维护时间段。",
		"ja": "RDS インスタンスにメンテナンスウィンドウが設定されていることを確認します。",
		"de": "Stellt sicher, dass die RDS-Instanz ein Wartungsfenster konfiguriert hat.",
		"es": "Garantiza que la instancia RDS tenga configurada una ventana de mantenimiento.",
		"fr": "Garantit que l'instance RDS a une fenêtre de maintenance configurée.",
		"pt": "Garante que a instância RDS tenha uma janela de manutenção configurada."
	},
	"reason": {
		"en": "Configuring a maintenance window allows for planned maintenance during off-peak hours.",
		"zh": "配置维护时间段允许在非高峰时段进行计划内维护。",
		"ja": "メンテナンスウィンドウを設定することで、オフピーク時間帯に計画的なメンテナンスを行うことができます。",
		"de": "Die Konfiguration eines Wartungsfensters ermöglicht geplante Wartungen während der Nebenzeiten.",
		"es": "Configurar una ventana de mantenimiento permite realizar mantenimiento planificado durante las horas de menor actividad.",
		"fr": "La configuration d'une fenêtre de maintenance permet d'effectuer une maintenance planifiée pendant les heures creuses.",
		"pt": "Configurar uma janela de manutenção permite realizar manutenção planejada durante as horas de menor movimento."
	},
	"recommendation": {
		"en": "Set maintain_time for the RDS instance to specify a maintenance window.",
		"zh": "为 RDS 实例设置 maintain_time 以指定维护时间段。",
		"ja": "RDS インスタンスの maintain_time を設定してメンテナンスウィンドウを指定します。",
		"de": "Setzen Sie maintain_time für die RDS-Instanz, um ein Wartungsfenster festzulegen.",
		"es": "Establezca maintain_time para la instancia RDS para especificar una ventana de mantenimiento.",
		"fr": "Définissez maintain_time pour l'instance RDS pour spécifier une fenêtre de maintenance.",
		"pt": "Defina maintain_time para a instância RDS para especificar uma janela de manutenção."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	maintain_time := tf.get_attribute(resource, "maintain_time", "")
	maintain_time == ""
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
