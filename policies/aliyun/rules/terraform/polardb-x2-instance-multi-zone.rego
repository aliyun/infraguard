package infraguard.rules.terraform.polardb_x2_instance_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

# Rule metadata
rule_meta := {
	"id": "polardb-x2-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "PolarDB-X 2.0 Instance Multi-Zone Deployment",
		"zh": "PolarDB-X 2.0 实例多可用区部署",
		"ja": "PolarDB-X 2.0 インスタンスのマルチゾーン展開",
		"de": "PolarDB-X 2.0-Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Instancia PolarDB-X 2.0",
		"fr": "Déploiement Multi-Zone de l'Instance PolarDB-X 2.0",
		"pt": "Implantação Multi-Zona da Instância PolarDB-X 2.0"
	},
	"description": {
		"en": "PolarDB-X 2.0 instances should be deployed across multiple availability zones.",
		"zh": "PolarDB-X 2.0 实例应部署在多个可用区。",
		"ja": "PolarDB-X 2.0 インスタンスは複数の可用性ゾーンにまたがって展開する必要があります。",
		"de": "PolarDB-X 2.0-Instanzen sollten über mehrere Verfügbarkeitszonen hinweg bereitgestellt werden.",
		"es": "Las instancias PolarDB-X 2.0 deben desplegarse en múltiples zonas de disponibilidad.",
		"fr": "Les instances PolarDB-X 2.0 doivent être déployées sur plusieurs zones de disponibilité.",
		"pt": "As instâncias PolarDB-X 2.0 devem ser implantadas em múltiplas zonas de disponibilidade."
	},
	"reason": {
		"en": "The PolarDB-X 2.0 instance is not configured with multi-zone deployment (zone_id does not indicate MAZ).",
		"zh": "PolarDB-X 2.0 实例未配置多可用区部署（zone_id 未包含 MAZ 标识）。",
		"ja": "PolarDB-X 2.0 インスタンスにマルチゾーン展開が設定されていません（zone_id に MAZ が含まれていません）。",
		"de": "Die PolarDB-X 2.0-Instanz ist nicht mit Multi-Zone-Bereitstellung konfiguriert (zone_id enthält kein MAZ).",
		"es": "La instancia PolarDB-X 2.0 no está configurada con despliegue multi-zona (zone_id no indica MAZ).",
		"fr": "L'instance PolarDB-X 2.0 n'est pas configurée avec un déploiement multi-zone (zone_id n'indique pas MAZ).",
		"pt": "A instância PolarDB-X 2.0 não está configurada com implantação multi-zona (zone_id não indica MAZ)."
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
	"resource_types": ["alicloud_drds_polardbx_instance"],
	"iac_type": "terraform"
}

is_multi_zone(resource) if {
	topology_type := tf.get_attribute(resource, "topology_type", "")
	not tf.is_unknown(topology_type)
	topology_type == "3azones"
}

is_multi_zone(resource) if {
	zone_id := tf.get_attribute(resource, "zone_id", "")
	not tf.is_unknown(zone_id)
	contains(zone_id, "MAZ")
}

# Deny rule
deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_drds_polardbx_instance")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_drds_polardbx_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
