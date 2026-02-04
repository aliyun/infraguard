package infraguard.rules.aliyun.polardb_cluster_default_time_zone_not_system

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "polardb-cluster-default-time-zone-not-system",
	"severity": "medium",
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
		"en": "Ensures PolarDB cluster default time zone is not set to SYSTEM.",
		"zh": "确保 PolarDB 集群的默认时区参数值不等于 SYSTEM。",
		"ja": "PolarDB クラスタのデフォルトタイムゾーンが SYSTEM に設定されていないことを確認します。",
		"de": "Stellt sicher, dass die Standard-Zeitzone des PolarDB-Clusters nicht auf SYSTEM gesetzt ist.",
		"es": "Garantiza que la zona horaria predeterminada del clúster PolarDB no esté establecida en SYSTEM.",
		"fr": "Garantit que le fuseau horaire par défaut du cluster PolarDB n'est pas défini sur SYSTEM.",
		"pt": "Garante que o fuso horário padrão do cluster PolarDB não esteja definido como SYSTEM."
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
		"en": "Set an explicit timezone for the PolarDB cluster.",
		"zh": "为 PolarDB 集群设置明确的时区。",
		"ja": "PolarDB クラスタに明示的なタイムゾーンを設定します。",
		"de": "Setzen Sie eine explizite Zeitzone für den PolarDB-Cluster.",
		"es": "Establezca una zona horaria explícita para el clúster PolarDB.",
		"fr": "Définissez un fuseau horaire explicite pour le cluster PolarDB.",
		"pt": "Defina um fuso horário explícito para o cluster PolarDB."
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"]
}

is_compliant(resource) if {
	db_cluster_params := helpers.get_property(resource, "DBClusterParameters", {})
	params_json := db_cluster_params.Parameters
	is_string(params_json)
	params_json != ""
	params := json.unmarshal(params_json)
	default_time_zone := params.default_time_zone
	default_time_zone != null
	default_time_zone != "SYSTEM"
}

is_compliant(resource) if {
	db_cluster_params := helpers.get_property(resource, "DBClusterParameters", {})
	db_cluster_params == {}
}

is_compliant(resource) if {
	db_cluster_params := helpers.get_property(resource, "DBClusterParameters", {})
	db_cluster_params != {}
	db_cluster_params.Parameters == null
}

is_compliant(resource) if {
	db_cluster_params := helpers.get_property(resource, "DBClusterParameters", {})
	params_json := db_cluster_params.Parameters
	is_string(params_json)
	params_json == ""
}

is_compliant(resource) if {
	db_cluster_params := helpers.get_property(resource, "DBClusterParameters", {})
	params_json := db_cluster_params.Parameters
	is_string(params_json)
	params_json != ""
	params := json.unmarshal(params_json)
	params.default_time_zone == null
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DBClusterParameters", "Parameters", "default_time_zone"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
