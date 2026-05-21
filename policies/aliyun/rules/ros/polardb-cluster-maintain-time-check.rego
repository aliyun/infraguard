package infraguard.rules.aliyun.polardb_cluster_maintain_time_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "polardb-cluster-maintain-time-check",
	"severity": "low",
	"name": {
		"en": "PolarDB Cluster Maintenance Window Check",
		"zh": "PolarDB 集群维护时间检测",
		"ja": "PolarDB クラスタのメンテナンスウィンドウチェック",
		"de": "PolarDB-Cluster Wartungsfenster-Prüfung",
		"es": "Verificación de Ventana de Mantenimiento de Cluster PolarDB",
		"fr": "Vérification de la Fenêtre de Maintenance du Cluster PolarDB",
		"pt": "Verificação de Janela de Manutenção de Cluster PolarDB"
	},
	"description": {
		"en": "Ensures that the PolarDB cluster has a maintenance window configured.",
		"zh": "确保 PolarDB 集群配置了维护时间段。",
		"ja": "PolarDB クラスタにメンテナンスウィンドウが設定されていることを確認します。",
		"de": "Stellt sicher, dass der PolarDB-Cluster ein Wartungsfenster konfiguriert hat.",
		"es": "Garantiza que el clúster PolarDB tenga una ventana de mantenimiento configurada.",
		"fr": "Garantit que le cluster PolarDB a une fenêtre de maintenance configurée.",
		"pt": "Garante que o cluster PolarDB tenha uma janela de manutenção configurada."
	},
	"reason": {
		"en": "Configuring a maintenance window allows for planned maintenance during off-peak hours.",
		"zh": "配置维护时间段允许在非高峰时段进行计划内维护。",
		"ja": "メンテナンスウィンドウを設定することで、オフピーク時間帯に計画的なメンテナンスを行うことができます。",
		"de": "Die Konfiguration eines Wartungsfensters ermöglicht geplante Wartung während der Nebenzeiten.",
		"es": "Configurar una ventana de mantenimiento permite realizar mantenimiento planificado durante las horas de menor actividad.",
		"fr": "Configurer une fenêtre de maintenance permet d'effectuer une maintenance planifiée pendant les heures creuses.",
		"pt": "Configurar uma janela de manutenção permite manutenção planejada durante horários de baixa demanda."
	},
	"recommendation": {
		"en": "Configure a maintenance window for the PolarDB cluster.",
		"zh": "为 PolarDB 集群配置维护时间段。",
		"ja": "PolarDB クラスタにメンテナンスウィンドウを設定します。",
		"de": "Konfigurieren Sie ein Wartungsfenster für den PolarDB-Cluster.",
		"es": "Configure una ventana de mantenimiento para el clúster PolarDB.",
		"fr": "Configurez une fenêtre de maintenance pour le cluster PolarDB.",
		"pt": "Configure uma janela de manutenção para o cluster PolarDB."
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
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
