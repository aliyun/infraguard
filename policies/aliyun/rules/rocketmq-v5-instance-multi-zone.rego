package infraguard.rules.aliyun.rocketmq_v5_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rocketmq-v5-instance-multi-zone",
	"name": {
		"en": "RocketMQ 5.0 Instance Multi-Zone Deployment",
		"zh": "使用多可用区的消息队列 RocketMQ 5.0 版实例",
		"ja": "RocketMQ 5.0 インスタンスマルチゾーン展開",
		"de": "RocketMQ 5.0 Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Instancia RocketMQ 5.0",
		"fr": "Déploiement Multi-Zone d'Instance RocketMQ 5.0",
		"pt": "Implantações Multi-Zona de Instância RocketMQ 5.0",
	},
	"severity": "medium",
	"description": {
		"en": "RocketMQ 5.0 instances should be deployed in Cluster HA mode which supports multi-zone availability.",
		"zh": "使用多可用区的消息队列 RocketMQ 5.0 版实例，视为合规。",
		"ja": "RocketMQ 5.0 インスタンスは、マルチゾーン可用性をサポートする Cluster HA モードで展開する必要があります。",
		"de": "RocketMQ 5.0-Instanzen sollten im Cluster-HA-Modus bereitgestellt werden, der Multi-Zone-Verfügbarkeit unterstützt.",
		"es": "Las instancias RocketMQ 5.0 deben desplegarse en modo Cluster HA que admite disponibilidad multi-zona.",
		"fr": "Les instances RocketMQ 5.0 doivent être déployées en mode Cluster HA qui prend en charge la disponibilité multi-zone.",
		"pt": "As instâncias RocketMQ 5.0 devem ser implantadas no modo Cluster HA que suporta disponibilidade multi-zona.",
	},
	"reason": {
		"en": "The RocketMQ 5.0 instance is not configured with Cluster HA mode.",
		"zh": "RocketMQ 5.0 实例未配置为高可用集群模式。",
		"ja": "RocketMQ 5.0 インスタンスが Cluster HA モードで設定されていません。",
		"de": "Die RocketMQ 5.0-Instanz ist nicht mit Cluster-HA-Modus konfiguriert.",
		"es": "La instancia RocketMQ 5.0 no está configurada con modo Cluster HA.",
		"fr": "L'instance RocketMQ 5.0 n'est pas configurée en mode Cluster HA.",
		"pt": "A instância RocketMQ 5.0 não está configurada com modo Cluster HA.",
	},
	"recommendation": {
		"en": "Set SubSeriesCode to 'cluster_ha'.",
		"zh": "将 SubSeriesCode 设置为'cluster_ha'。",
		"ja": "SubSeriesCode を 'cluster_ha' に設定します。",
		"de": "Setzen Sie SubSeriesCode auf 'cluster_ha'.",
		"es": "Establezca SubSeriesCode en 'cluster_ha'.",
		"fr": "Définissez SubSeriesCode sur 'cluster_ha'.",
		"pt": "Defina SubSeriesCode como 'cluster_ha'.",
	},
	"resource_types": ["ALIYUN::ROCKETMQ5::Instance"],
}

# Check if instance is multi-zone (cluster_ha)
is_multi_zone(resource) if {
	resource.Properties.SubSeriesCode == "cluster_ha"
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SubSeriesCode"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
