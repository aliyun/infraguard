package infraguard.rules.aliyun.kafka_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "kafka-instance-multi-zone",
	"name": {
		"en": "Kafka Instance Multi-Zone Deployment",
		"zh": "使用多可用区的消息队列 Kafka 版实例",
		"ja": "Kafka インスタンスのマルチゾーン展開",
		"de": "Kafka-Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Instancia Kafka",
		"fr": "Déploiement Multi-Zone de l'Instance Kafka",
		"pt": "Implantação Multi-Zona da Instância Kafka"
	},
	"severity": "medium",
	"description": {
		"en": "Kafka instances should be deployed across multiple availability zones for high availability.",
		"zh": "使用多可用区的消息队列 Kafka 版实例，视为合规。",
		"ja": "Kafka インスタンスは高可用性のために複数の可用性ゾーンにまたがって展開する必要があります。",
		"de": "Kafka-Instanzen sollten für hohe Verfügbarkeit über mehrere Verfügbarkeitszonen hinweg bereitgestellt werden.",
		"es": "Las instancias Kafka deben desplegarse en múltiples zonas de disponibilidad para alta disponibilidad.",
		"fr": "Les instances Kafka doivent être déployées sur plusieurs zones de disponibilité pour une haute disponibilité.",
		"pt": "As instâncias Kafka devem ser implantadas em múltiplas zonas de disponibilidade para alta disponibilidade."
	},
	"reason": {
		"en": "The Kafka instance is not configured for cross-zone deployment or multiple selected zones.",
		"zh": "Kafka 实例未配置跨可用区部署或未选择多个可用区。",
		"ja": "Kafka インスタンスがクロスゾーン展開または複数の選択されたゾーン用に設定されていません。",
		"de": "Die Kafka-Instanz ist nicht für die Cross-Zone-Bereitstellung oder mehrere ausgewählte Zonen konfiguriert.",
		"es": "La instancia Kafka no está configurada para despliegue entre zonas o múltiples zonas seleccionadas.",
		"fr": "L'instance Kafka n'est pas configurée pour le déploiement inter-zones ou plusieurs zones sélectionnées.",
		"pt": "A instância Kafka não está configurada para implantação entre zonas ou múltiplas zonas selecionadas."
	},
	"recommendation": {
		"en": "Enable CrossZone or specify at least 2 zones in SelectedZones.",
		"zh": "启用 CrossZone 或在 SelectedZones 中指定至少 2 个可用区。",
		"ja": "CrossZone を有効にするか、SelectedZones で少なくとも 2 つのゾーンを指定します。",
		"de": "Aktivieren Sie CrossZone oder geben Sie mindestens 2 Zonen in SelectedZones an.",
		"es": "Habilite CrossZone o especifique al menos 2 zonas en SelectedZones.",
		"fr": "Activez CrossZone ou spécifiez au moins 2 zones dans SelectedZones.",
		"pt": "Habilite CrossZone ou especifique pelo menos 2 zonas em SelectedZones."
	},
	"resource_types": ["ALIYUN::KAFKA::Instance"],
}

# Check if instance is multi-zone
is_multi_zone(resource) if {
	# Method 1: DeployOption.CrossZone is set to true
	deploy_option := object.get(resource.Properties, "DeployOption", {})
	object.get(deploy_option, "CrossZone", false) == true
}

is_multi_zone(resource) if {
	# Method 2: DeployOption.SelectedZones count >= 2
	deploy_option := object.get(resource.Properties, "DeployOption", {})
	selected_zones := object.get(deploy_option, "SelectedZones", [])
	count(selected_zones) >= 2
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "CrossZone"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
