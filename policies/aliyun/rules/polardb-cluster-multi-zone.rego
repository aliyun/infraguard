package infraguard.rules.aliyun.polardb_cluster_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "polardb-cluster-multi-zone",
	"name": {
		"en": "PolarDB Cluster Multi-Zone Deployment",
		"zh": "PolarDB 集群多可用区部署",
		"ja": "PolarDB クラスタのマルチゾーン展開",
		"de": "PolarDB-Cluster Multi-Zone-Bereitstellung",
		"es": "Implementación Multi-zona de Cluster PolarDB",
		"fr": "Déploiement Multi-zones du Cluster PolarDB",
		"pt": "Implantação Multi-zona de Cluster PolarDB",
	},
	"severity": "medium",
	"description": {
		"en": "PolarDB clusters should be deployed across multiple availability zones for high availability.",
		"zh": "PolarDB 集群应部署在多个可用区。",
		"ja": "高可用性のために、PolarDB クラスタは複数の可用性ゾーンに展開する必要があります。",
		"de": "PolarDB-Cluster sollten für hohe Verfügbarkeit über mehrere Verfügbarkeitszonen bereitgestellt werden.",
		"es": "Los clústeres PolarDB deben implementarse en múltiples zonas de disponibilidad para alta disponibilidad.",
		"fr": "Les clusters PolarDB doivent être déployés sur plusieurs zones de disponibilité pour une haute disponibilité.",
		"pt": "Clusters PolarDB devem ser implantados em múltiplas zonas de disponibilidade para alta disponibilidade.",
	},
	"reason": {
		"en": "The PolarDB cluster is not configured with a standby availability zone.",
		"zh": "PolarDB 集群未配置备用可用区。",
		"ja": "PolarDB クラスタにスタンバイ可用性ゾーンが設定されていません。",
		"de": "Der PolarDB-Cluster ist nicht mit einer Standby-Verfügbarkeitszone konfiguriert.",
		"es": "El clúster PolarDB no está configurado con una zona de disponibilidad en espera.",
		"fr": "Le cluster PolarDB n'est pas configuré avec une zone de disponibilité de secours.",
		"pt": "O cluster PolarDB não está configurado com uma zona de disponibilidade em espera.",
	},
	"recommendation": {
		"en": "Configure StandbyAZ to enable multi-zone deployment.",
		"zh": "配置 StandbyAZ 以启用多可用区部署。",
		"ja": "マルチゾーン展開を有効にするために StandbyAZ を設定します。",
		"de": "Konfigurieren Sie StandbyAZ, um Multi-Zone-Bereitstellung zu aktivieren.",
		"es": "Configure StandbyAZ para habilitar la implementación multi-zona.",
		"fr": "Configurez StandbyAZ pour activer le déploiement multi-zones.",
		"pt": "Configure StandbyAZ para habilitar a implantação multi-zona.",
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

# Check if cluster is multi-zone
is_multi_zone(resource) if {
	# Check if StandbyAZ is present and not empty
	object.get(resource.Properties, "StandbyAZ", "") != ""
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "StandbyAZ"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
