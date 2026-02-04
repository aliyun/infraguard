package infraguard.rules.aliyun.rds_instance_maintain_time_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rds-instance-maintain-time-check",
	"name": {
		"en": "RDS Instance Maintenance Window Check",
		"zh": "RDS 实例维护时间检测",
		"ja": "RDS インスタンスのメンテナンスウィンドウチェック",
		"de": "RDS-Instanz Wartungsfenster-Prüfung",
		"es": "Verificación de Ventana de Mantenimiento de Instancia RDS",
		"fr": "Vérification de la Fenêtre de Maintenance de l'Instance RDS",
		"pt": "Verificação de Janela de Manutenção de Instância RDS",
	},
	"severity": "low",
	"description": {
		"en": "Ensures that the RDS instance has a maintenance window configured.",
		"zh": "确保 RDS 实例配置了维护时间段。",
		"ja": "RDS インスタンスにメンテナンスウィンドウが設定されていることを確認します。",
		"de": "Stellt sicher, dass die RDS-Instanz ein Wartungsfenster konfiguriert hat.",
		"es": "Garantiza que la instancia RDS tenga configurada una ventana de mantenimiento.",
		"fr": "Garantit que l'instance RDS a une fenêtre de maintenance configurée.",
		"pt": "Garante que a instância RDS tenha uma janela de manutenção configurada.",
	},
	"reason": {
		"en": "Configuring a maintenance window allows for planned maintenance during off-peak hours.",
		"zh": "配置维护时间段允许在非高峰时段进行计划内维护。",
		"ja": "メンテナンスウィンドウを設定することで、オフピーク時間帯に計画的なメンテナンスを行うことができます。",
		"de": "Die Konfiguration eines Wartungsfensters ermöglicht geplante Wartungen während der Nebenzeiten.",
		"es": "Configurar una ventana de mantenimiento permite realizar mantenimiento planificado durante las horas de menor actividad.",
		"fr": "La configuration d'une fenêtre de maintenance permet d'effectuer une maintenance planifiée pendant les heures creuses.",
		"pt": "Configurar uma janela de manutenção permite realizar manutenção planejada durante as horas de menor movimento.",
	},
	"recommendation": {
		"en": "Configure a maintenance window for the RDS instance.",
		"zh": "为 RDS 实例配置维护时间段。",
		"ja": "RDS インスタンスにメンテナンスウィンドウを設定します。",
		"de": "Konfigurieren Sie ein Wartungsfenster für die RDS-Instanz.",
		"es": "Configure una ventana de mantenimiento para la instancia RDS.",
		"fr": "Configurez une fenêtre de maintenance pour l'instance RDS.",
		"pt": "Configure uma janela de manutenção para a instância RDS.",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not helpers.has_property(resource, "MaintainTime")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "MaintainTime"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
