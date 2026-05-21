package infraguard.rules.terraform.polardb_cluster_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

# Rule metadata
rule_meta := {
	"id": "polardb-cluster-multi-zone",
	"severity": "medium",
	"name": {
		"en": "PolarDB Cluster Multi-Zone Deployment",
		"zh": "PolarDB 集群多可用区部署",
		"ja": "PolarDB クラスタのマルチゾーン展開",
		"de": "PolarDB-Cluster Multi-Zone-Bereitstellung",
		"es": "Implementación Multi-zona de Cluster PolarDB",
		"fr": "Déploiement Multi-zones du Cluster PolarDB",
		"pt": "Implantação Multi-zona de Cluster PolarDB"
	},
	"description": {
		"en": "PolarDB clusters should be deployed across multiple availability zones for high availability.",
		"zh": "PolarDB 集群应部署在多个可用区。",
		"ja": "高可用性のために、PolarDB クラスタは複数の可用性ゾーンに展開する必要があります。",
		"de": "PolarDB-Cluster sollten für hohe Verfügbarkeit über mehrere Verfügbarkeitszonen bereitgestellt werden.",
		"es": "Los clústeres PolarDB deben implementarse en múltiples zonas de disponibilidad para alta disponibilidad.",
		"fr": "Les clusters PolarDB doivent être déployés sur plusieurs zones de disponibilité pour une haute disponibilité.",
		"pt": "Clusters PolarDB devem ser implantados em múltiplas zonas de disponibilidade para alta disponibilidade."
	},
	"reason": {
		"en": "The PolarDB cluster is not configured with a multi-zone deployment (zone_id does not indicate MAZ).",
		"zh": "PolarDB 集群未配置多可用区部署（zone_id 未包含 MAZ 标识）。",
		"ja": "PolarDB クラスタにマルチゾーン展開が設定されていません（zone_id に MAZ が含まれていません）。",
		"de": "Der PolarDB-Cluster ist nicht mit einer Multi-Zone-Bereitstellung konfiguriert (zone_id enthält kein MAZ).",
		"es": "El clúster PolarDB no está configurado con despliegue multi-zona (zone_id no indica MAZ).",
		"fr": "Le cluster PolarDB n'est pas configuré avec un déploiement multi-zone (zone_id n'indique pas MAZ).",
		"pt": "O cluster PolarDB não está configurado com implantação multi-zona (zone_id não indica MAZ)."
	},
	"recommendation": {
		"en": "Set zone_id to a Multi-AZ zone ID (containing 'MAZ') to enable multi-zone deployment.",
		"zh": "将 zone_id 设置为多可用区 ID（包含 'MAZ'）以启用多可用区部署。",
		"ja": "マルチゾーン展開を有効にするために zone_id をマルチ AZ ゾーン ID（'MAZ' を含む）に設定します。",
		"de": "Setzen Sie zone_id auf eine Multi-AZ-Zonen-ID (mit 'MAZ'), um Multi-Zone-Bereitstellung zu aktivieren.",
		"es": "Configure zone_id con un ID de zona Multi-AZ (que contenga 'MAZ') para habilitar el despliegue multi-zona.",
		"fr": "Définissez zone_id sur un ID de zone Multi-AZ (contenant 'MAZ') pour activer le déploiement multi-zone.",
		"pt": "Defina zone_id com um ID de zona Multi-AZ (contendo 'MAZ') para habilitar a implantação multi-zona."
	},
	"resource_types": ["alicloud_polardb_cluster"],
	"iac_type": "terraform"
}

# Check if cluster is multi-zone (zone_id contains "MAZ")
is_multi_zone(resource) if {
	zone_id := tf.get_attribute(resource, "zone_id", "")
	not tf.is_unknown(zone_id)
	contains(zone_id, "MAZ")
}

# Deny rule
deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_polardb_cluster")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_polardb_cluster.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
