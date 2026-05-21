package infraguard.rules.terraform.elasticsearch_instance_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "elasticsearch-instance-multi-zone",
	"severity": "medium",
	"name": {"en": "Elasticsearch Instance Multi-Zone Deployment", "zh": "Elasticsearch 实例多可用区部署", "ja": "Elasticsearch インスタンスマルチゾーン展開", "de": "Elasticsearch-Instanz Multi-Zonen-Bereitstellung", "es": "Implementación Multi-Zona de Instancia Elasticsearch", "fr": "Déploiement Multi-Zone d'Instance Elasticsearch", "pt": "Implantação Multi-Zona de Instância Elasticsearch"},
	"description": {"en": "Elasticsearch instances should be deployed across multiple availability zones.", "zh": "Elasticsearch 实例应部署在多个可用区。", "ja": "Elasticsearch インスタンスは複数の可用性ゾーンに展開する必要があります。", "de": "Elasticsearch-Instanzen sollten über mehrere Verfügbarkeitszonen hinweg bereitgestellt werden.", "es": "Las instancias Elasticsearch deben implementarse en múltiples zonas de disponibilidad.", "fr": "Les instances Elasticsearch doivent être déployées sur plusieurs zones de disponibilité.", "pt": "As instâncias Elasticsearch devem ser implantadas em múltiplas zonas de disponibilidade."},
	"reason": {"en": "The Elasticsearch instance is configured with fewer than 2 availability zones.", "zh": "Elasticsearch 实例配置的可用区数量少于 2 个。", "ja": "Elasticsearch インスタンスが 2 未満の可用性ゾーンで設定されています。", "de": "Die Elasticsearch-Instanz ist mit weniger als 2 Verfügbarkeitszonen konfiguriert.", "es": "La instancia Elasticsearch está configurada con menos de 2 zonas de disponibilidad.", "fr": "L'instance Elasticsearch est configurée avec moins de 2 zones de disponibilité.", "pt": "A instância Elasticsearch está configurada com menos de 2 zonas de disponibilidade."},
	"recommendation": {"en": "Increase the ZoneCount to at least 2.", "zh": "将 ZoneCount 增加到至少 2。", "ja": "ZoneCount を少なくとも 2 に増やします。", "de": "Erhöhen Sie ZoneCount auf mindestens 2.", "es": "Aumente ZoneCount a al menos 2.", "fr": "Augmentez ZoneCount à au moins 2.", "pt": "Aumente ZoneCount para pelo menos 2."},
	"resource_types": ["alicloud_elasticsearch_instance"],
	"iac_type": "terraform"
}

is_multi_zone(resource) if {
	zone_count := tf.get_attribute(resource, "zone_count", 1)
	not tf.is_unknown(zone_count)
	zone_count >= 2
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_elasticsearch_instance")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_elasticsearch_instance.%s", [name]),
		"violation_path": ["zone_count"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
