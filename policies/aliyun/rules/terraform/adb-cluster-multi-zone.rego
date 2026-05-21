package infraguard.rules.terraform.adb_cluster_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

# Rule metadata
rule_meta := {
	"id": "adb-cluster-multi-zone",
	"severity": "medium",
	"name": {
		"en": "ADB Cluster Multi-Zone Deployment",
		"zh": "ADB 集群部署模式为多可用区",
		"ja": "ADB クラスターマルチゾーン展開",
		"de": "ADB-Cluster Multi-Zonen-Bereitstellung",
		"es": "Implementación Multi-Zona del Clúster ADB",
		"fr": "Déploiement Multi-Zone du Cluster ADB",
		"pt": "Implantação Multi-Zona do Cluster ADB"
	},
	"description": {
		"en": "The ADB cluster should be deployed in multi-zone mode.",
		"zh": "ADB 集群为多可用区部署模式，视为合规。",
		"ja": "ADB クラスターはマルチゾーンモードで展開する必要があります。",
		"de": "Der ADB-Cluster sollte im Multi-Zonen-Modus bereitgestellt werden.",
		"es": "El clúster ADB debe implementarse en modo multi-zona.",
		"fr": "Le cluster ADB doit être déployé en mode multi-zone.",
		"pt": "O cluster ADB deve ser implantado em modo multi-zona."
	},
	"reason": {
		"en": "The ADB cluster is not configured with a secondary zone, indicating it is single-zone.",
		"zh": "ADB 集群未配置备可用区，表明其为单可用区部署。",
		"ja": "ADB クラスターにセカンダリゾーンが設定されていないため、シングルゾーンであることを示しています。",
		"de": "Der ADB-Cluster ist nicht mit einer sekundären Zone konfiguriert, was darauf hindeutet, dass es sich um eine Einzelzone handelt.",
		"es": "El clúster ADB no está configurado con una zona secundaria, lo que indica que es de zona única.",
		"fr": "Le cluster ADB n'est pas configuré avec une zone secondaire, indiquant qu'il s'agit d'une zone unique.",
		"pt": "O cluster ADB não está configurado com uma zona secundária, indicando que é de zona única."
	},
	"recommendation": {
		"en": "Configure the secondary_zone_id to enable multi-zone deployment.",
		"zh": "配置 secondary_zone_id 以启用多可用区部署。",
		"ja": "マルチゾーン展開を有効にするために secondary_zone_id を設定します。",
		"de": "Konfigurieren Sie secondary_zone_id, um Multi-Zonen-Bereitstellung zu aktivieren.",
		"es": "Configure secondary_zone_id para habilitar la implementación multi-zona.",
		"fr": "Configurez secondary_zone_id pour activer le déploiement multi-zone.",
		"pt": "Configure secondary_zone_id para habilitar a implantação multi-zona."
	},
	"resource_types": ["alicloud_adb_db_cluster_lake_version"],
	"iac_type": "terraform"
}

# Check if ADB is multi-zone
is_multi_zone(resource) if {
	secondary_zone_id := tf.get_attribute(resource, "secondary_zone_id", "")
	not tf.is_unknown(secondary_zone_id)
	secondary_zone_id != ""
}

# Deny rule
deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_adb_db_cluster_lake_version")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_adb_db_cluster_lake_version.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
