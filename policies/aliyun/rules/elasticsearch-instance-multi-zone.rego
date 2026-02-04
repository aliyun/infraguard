package infraguard.rules.aliyun.elasticsearch_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "elasticsearch-instance-multi-zone",
	"name": {
		"en": "Elasticsearch Instance Multi-Zone Deployment",
		"zh": "Elasticsearch 实例多可用区部署",
		"ja": "Elasticsearch インスタンスマルチゾーン展開",
		"de": "Elasticsearch-Instanz Multi-Zonen-Bereitstellung",
		"es": "Implementación Multi-Zona de Instancia Elasticsearch",
		"fr": "Déploiement Multi-Zone d'Instance Elasticsearch",
		"pt": "Implantação Multi-Zona de Instância Elasticsearch",
	},
	"severity": "medium",
	"description": {
		"en": "Elasticsearch instances should be deployed across multiple availability zones.",
		"zh": "Elasticsearch 实例应部署在多个可用区。",
		"ja": "Elasticsearch インスタンスは複数の可用性ゾーンに展開する必要があります。",
		"de": "Elasticsearch-Instanzen sollten über mehrere Verfügbarkeitszonen hinweg bereitgestellt werden.",
		"es": "Las instancias Elasticsearch deben implementarse en múltiples zonas de disponibilidad.",
		"fr": "Les instances Elasticsearch doivent être déployées sur plusieurs zones de disponibilité.",
		"pt": "As instâncias Elasticsearch devem ser implantadas em múltiplas zonas de disponibilidade.",
	},
	"reason": {
		"en": "The Elasticsearch instance is configured with fewer than 2 availability zones.",
		"zh": "Elasticsearch 实例配置的可用区数量少于 2 个。",
		"ja": "Elasticsearch インスタンスが 2 未満の可用性ゾーンで設定されています。",
		"de": "Die Elasticsearch-Instanz ist mit weniger als 2 Verfügbarkeitszonen konfiguriert.",
		"es": "La instancia Elasticsearch está configurada con menos de 2 zonas de disponibilidad.",
		"fr": "L'instance Elasticsearch est configurée avec moins de 2 zones de disponibilité.",
		"pt": "A instância Elasticsearch está configurada com menos de 2 zonas de disponibilidade.",
	},
	"recommendation": {
		"en": "Increase the ZoneCount to at least 2.",
		"zh": "将 ZoneCount 增加到至少 2。",
		"ja": "ZoneCount を少なくとも 2 に増やします。",
		"de": "Erhöhen Sie ZoneCount auf mindestens 2.",
		"es": "Aumente ZoneCount a al menos 2.",
		"fr": "Augmentez ZoneCount à au moins 2.",
		"pt": "Aumente ZoneCount para pelo menos 2.",
	},
	"resource_types": ["ALIYUN::ElasticSearch::Instance"],
}

# Check if instance is multi-zone
is_multi_zone(resource) if {
	# Check ZoneCount >= 2
	object.get(resource.Properties, "ZoneCount", 1) >= 2
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ZoneCount"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
