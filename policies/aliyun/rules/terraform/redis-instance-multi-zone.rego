package infraguard.rules.terraform.redis_instance_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "Redis Instance Multi-Zone Deployment",
		"zh": "Redis 实例多可用区部署",
		"ja": "Redis インスタンスのマルチゾーン展開",
		"de": "Redis-Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-zona de Instancia Redis",
		"fr": "Déploiement Multi-Zones d'Instance Redis",
		"pt": "Implantação Multi-zona de Instância Redis"
	},
	"description": {
		"en": "Redis instances should be deployed across multiple availability zones for high availability.",
		"zh": "Redis 实例应部署在多个可用区。",
		"ja": "高可用性のために、Redis インスタンスは複数の可用性ゾーンに展開する必要があります。",
		"de": "Redis-Instanzen sollten für hohe Verfügbarkeit über mehrere Verfügbarkeitszonen bereitgestellt werden.",
		"es": "Las instancias Redis deben implementarse en múltiples zonas de disponibilidad para alta disponibilidad.",
		"fr": "Les instances Redis doivent être déployées sur plusieurs zones de disponibilité pour une haute disponibilité.",
		"pt": "Instâncias Redis devem ser implantadas em múltiplas zonas de disponibilidade para alta disponibilidade."
	},
	"reason": {
		"en": "The Redis instance is not configured with a secondary zone.",
		"zh": "Redis 实例未配置备用可用区。",
		"ja": "Redis インスタンスにセカンダリゾーンが設定されていません。",
		"de": "Die Redis-Instanz ist nicht mit einer sekundären Zone konfiguriert.",
		"es": "La instancia Redis no está configurada con una zona secundaria.",
		"fr": "L'instance Redis n'est pas configurée avec une zone secondaire.",
		"pt": "A instância Redis não está configurada com uma zona secundária."
	},
	"recommendation": {
		"en": "Configure secondary_zone_id to enable multi-zone deployment.",
		"zh": "配置 secondary_zone_id 以启用多可用区部署。",
		"ja": "マルチゾーン展開を有効にするために secondary_zone_id を設定します。",
		"de": "Konfigurieren Sie secondary_zone_id, um Multi-Zone-Bereitstellung zu aktivieren.",
		"es": "Configure secondary_zone_id para habilitar la implementación multi-zona.",
		"fr": "Configurez secondary_zone_id pour activer le déploiement multi-zones.",
		"pt": "Configure secondary_zone_id para habilitar implantação multi-zona."
	},
	"resource_types": ["alicloud_kvstore_instance"],
	"iac_type": "terraform"
}

is_multi_zone(resource) if {
	secondary_zone_id := tf.get_attribute(resource, "secondary_zone_id", "")
	not tf.is_unknown(secondary_zone_id)
	secondary_zone_id != ""
	zone_id := tf.get_attribute(resource, "zone_id", "")
	secondary_zone_id != zone_id
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_kvstore_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
