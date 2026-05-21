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
		"en": "Set default_time_zone parameter to a specific timezone (e.g., '+08:00') instead of SYSTEM in the PolarDB cluster parameters.",
		"zh": "将 PolarDB 集群参数中的 default_time_zone 设置为具体时区（如 '+08:00'），而非 SYSTEM。",
		"ja": "PolarDB クラスタパラメータの default_time_zone を SYSTEM ではなく特定のタイムゾーン（例：'+08:00'）に設定します。",
		"de": "Setzen Sie den Parameter default_time_zone auf eine bestimmte Zeitzone (z.B. '+08:00') anstelle von SYSTEM in den PolarDB-Cluster-Parametern.",
		"es": "Establezca el parámetro default_time_zone en una zona horaria específica (p. ej., '+08:00') en lugar de SYSTEM en los parámetros del clúster PolarDB.",
		"fr": "Définissez le paramètre default_time_zone sur un fuseau horaire spécifique (par exemple, '+08:00') au lieu de SYSTEM dans les paramètres du cluster PolarDB.",
		"pt": "Defina o parâmetro default_time_zone para um fuso horário específico (ex.: '+08:00') em vez de SYSTEM nos parâmetros do cluster PolarDB."
	},
	"resource_types": ["alicloud_polardb_cluster"],
	"iac_type": "terraform"
}

as_array(v) := v if {
	is_array(v)
}

as_array(v) := [v] if {
	is_object(v)
}

as_array(v) := [] if {
	not is_array(v)
	not is_object(v)
}

has_explicit_timezone(resource) if {
	params := as_array(tf.get_attribute(resource, "parameters", []))
	some param in params
	object.get(param, "name", "") == "default_time_zone"
	value := object.get(param, "value", "SYSTEM")
	value != "SYSTEM"
	value != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_polardb_cluster")
	not has_explicit_timezone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_polardb_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
