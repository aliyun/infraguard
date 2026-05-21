package infraguard.rules.terraform.rocketmq_v5_instance_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rocketmq-v5-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "RocketMQ 5.0 Instance Multi-Zone Deployment",
		"zh": "使用多可用区的消息队列 RocketMQ 5.0 版实例",
		"ja": "RocketMQ 5.0 インスタンスマルチゾーン展開",
		"de": "RocketMQ 5.0 Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Instancia RocketMQ 5.0",
		"fr": "Déploiement Multi-Zone d'Instance RocketMQ 5.0",
		"pt": "Implantações Multi-Zona de Instância RocketMQ 5.0"
	},
	"description": {
		"en": "RocketMQ 5.0 instances should be deployed in Cluster HA mode which supports multi-zone availability.",
		"zh": "使用多可用区的消息队列 RocketMQ 5.0 版实例，视为合规。",
		"ja": "RocketMQ 5.0 インスタンスは、マルチゾーン可用性をサポートする Cluster HA モードで展開する必要があります。",
		"de": "RocketMQ 5.0-Instanzen sollten im Cluster-HA-Modus bereitgestellt werden, der Multi-Zone-Verfügbarkeit unterstützt.",
		"es": "Las instancias RocketMQ 5.0 deben desplegarse en modo Cluster HA que admite disponibilidad multi-zona.",
		"fr": "Les instances RocketMQ 5.0 doivent être déployées en mode Cluster HA qui prend en charge la disponibilité multi-zone.",
		"pt": "As instâncias RocketMQ 5.0 devem ser implantadas no modo Cluster HA que suporta disponibilidade multi-zona."
	},
	"reason": {
		"en": "The RocketMQ 5.0 instance is not configured with Cluster HA mode.",
		"zh": "RocketMQ 5.0 实例未配置为高可用集群模式。",
		"ja": "RocketMQ 5.0 インスタンスが Cluster HA モードで設定されていません。",
		"de": "Die RocketMQ 5.0-Instanz ist nicht mit Cluster-HA-Modus konfiguriert.",
		"es": "La instancia RocketMQ 5.0 no está configurada con modo Cluster HA.",
		"fr": "L'instance RocketMQ 5.0 n'est pas configurée en mode Cluster HA.",
		"pt": "A instância RocketMQ 5.0 não está configurada com modo Cluster HA."
	},
	"recommendation": {
		"en": "Set sub_series_code to 'cluster_ha'.",
		"zh": "将 sub_series_code 设置为 'cluster_ha'。",
		"ja": "sub_series_code を 'cluster_ha' に設定します。",
		"de": "Setzen Sie sub_series_code auf 'cluster_ha'.",
		"es": "Establezca sub_series_code en 'cluster_ha'.",
		"fr": "Définissez sub_series_code sur 'cluster_ha'.",
		"pt": "Defina sub_series_code como 'cluster_ha'."
	},
	"resource_types": ["alicloud_rocketmq_instance"],
	"iac_type": "terraform"
}

is_multi_zone(resource) if {
	tf.get_attribute(resource, "sub_series_code", "") == "cluster_ha"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_rocketmq_instance")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_rocketmq_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
