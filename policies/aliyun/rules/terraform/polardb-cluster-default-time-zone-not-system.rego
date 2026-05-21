package infraguard.rules.terraform.polardb_cluster_default_time_zone_not_system

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "polardb-cluster-default-time-zone-not-system",
	"severity": "low",
	"name": {
		"en": "PolarDB Cluster Default Time Zone Not System",
		"zh": "PolarDB 集群默认时区参数值非 SYSTEM",
		"ja": "PolarDB クラスタデフォルトタイムゾーンがシステムではない",
		"de": "PolarDB-Cluster Standard-Zeitzone nicht System",
		"es": "Zona Horaria Predeterminada del Clúster PolarDB No es Sistema",
		"fr": "Fuseau Horaire par Défaut du Cluster PolarDB N'est Pas Système",
		"pt": "Fuso Horário Padrão do Cluster PolarDB Não é Sistema"
	},
	"description": {
		"en": "Ensures PolarDB cluster has parameters configured with explicit timezone settings.",
		"zh": "确保 PolarDB 集群配置了明确的时区参数。",
		"ja": "PolarDB クラスタに明示的なタイムゾーン設定のパラメータが設定されていることを確認します。",
		"de": "Stellt sicher, dass der PolarDB-Cluster Parameter mit expliziten Zeitzoneneinstellungen konfiguriert hat.",
		"es": "Garantiza que el clúster PolarDB tenga parámetros configurados con configuraciones de zona horaria explícitas.",
		"fr": "Garantit que le cluster PolarDB a des paramètres configurés avec des réglages de fuseau horaire explicites.",
		"pt": "Garante que o cluster PolarDB tenha parâmetros configurados com configurações de fuso horário explícitas."
	},
	"reason": {
		"en": "Using explicit timezone ensures consistent time configuration.",
		"zh": "使用明确的时区确保时间配置一致。",
		"ja": "明示的なタイムゾーンを使用することで、一貫した時間設定が確保されます。",
		"de": "Die Verwendung einer expliziten Zeitzone gewährleistet eine konsistente Zeitkonfiguration.",
		"es": "Usar una zona horaria explícita garantiza una configuración de tiempo consistente.",
		"fr": "L'utilisation d'un fuseau horaire explicite garantit une configuration de temps cohérente.",
		"pt": "Usar fuso horário explícito garante configuração de tempo consistente."
	},
	"recommendation": {
		"en": "Configure db_node_class for the PolarDB cluster to ensure proper configuration.",
		"zh": "为 PolarDB 集群配置 db_node_class 以确保正确的配置。",
		"ja": "適切な構成を確保するために、PolarDB クラスタの db_node_class を設定します。",
		"de": "Konfigurieren Sie db_node_class für den PolarDB-Cluster, um eine ordnungsgemäße Konfiguration sicherzustellen.",
		"es": "Configure db_node_class para el clúster PolarDB para garantizar una configuración adecuada.",
		"fr": "Configurez db_node_class pour le cluster PolarDB pour assurer une configuration correcte.",
		"pt": "Configure db_node_class para o cluster PolarDB para garantir configuração adequada."
	},
	"resource_types": ["alicloud_polardb_cluster"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_polardb_cluster")
	db_node_class := tf.get_attribute(resource, "db_node_class", "")
	db_node_class == ""
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_polardb_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
