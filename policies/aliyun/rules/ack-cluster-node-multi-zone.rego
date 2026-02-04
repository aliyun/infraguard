package infraguard.rules.aliyun.ack_cluster_node_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ack-cluster-node-multi-zone",
	"name": {
		"en": "ACK Cluster Multi-Zone Deployment",
		"zh": "使用区域级多可用区 ACK 集群",
		"ja": "ACK クラスタのマルチゾーン展開",
		"de": "ACK-Cluster Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-zona del Cluster ACK",
		"fr": "Déploiement Multi-Zones du Cluster ACK",
		"pt": "Implantação Multi-zona do Cluster ACK",
	},
	"severity": "high",
	"description": {
		"en": "The ACK cluster nodes should be distributed across 3 or more availability zones for high availability.",
		"zh": "使用区域级 ACK 集群，节点分布在 3 个及以上可用区，视为合规。",
		"ja": "高可用性のために、ACK クラスタノードは 3 つ以上の可用性ゾーンに分散させる必要があります。",
		"de": "Die ACK-Cluster-Knoten sollten für hohe Verfügbarkeit über 3 oder mehr Verfügbarkeitszonen verteilt werden.",
		"es": "Los nodos del clúster ACK deben distribuirse en 3 o más zonas de disponibilidad para alta disponibilidad.",
		"fr": "Les nœuds du cluster ACK doivent être distribués sur 3 zones de disponibilité ou plus pour une haute disponibilité.",
		"pt": "Os nós do cluster ACK devem ser distribuídos em 3 ou mais zonas de disponibilidade para alta disponibilidade.",
	},
	"reason": {
		"en": "The ACK cluster nodes are not distributed across 3 or more availability zones.",
		"zh": "ACK 集群节点未分布在 3 个及以上可用区。",
		"ja": "ACK クラスタノードが 3 つ以上の可用性ゾーンに分散されていません。",
		"de": "Die ACK-Cluster-Knoten sind nicht über 3 oder mehr Verfügbarkeitszonen verteilt.",
		"es": "Los nodos del clúster ACK no están distribuidos en 3 o más zonas de disponibilidad.",
		"fr": "Les nœuds du cluster ACK ne sont pas distribués sur 3 zones de disponibilité ou plus.",
		"pt": "Os nós do cluster ACK não estão distribuídos em 3 ou mais zonas de disponibilidade.",
	},
	"recommendation": {
		"en": "Configure the cluster to use at least 3 availability zones by specifying multiple VSwitchIds.",
		"zh": "通过指定多个 VSwitchIds，将集群配置为使用至少 3 个可用区。",
		"ja": "複数の VSwitchIds を指定して、クラスタを少なくとも 3 つの可用性ゾーンを使用するように設定します。",
		"de": "Konfigurieren Sie den Cluster so, dass er mindestens 3 Verfügbarkeitszonen verwendet, indem Sie mehrere VSwitchIds angeben.",
		"es": "Configure el clúster para usar al menos 3 zonas de disponibilidad especificando múltiples VSwitchIds.",
		"fr": "Configurez le cluster pour utiliser au moins 3 zones de disponibilité en spécifiant plusieurs VSwitchIds.",
		"pt": "Configure o cluster para usar pelo menos 3 zonas de disponibilidade especificando múltiplos VSwitchIds.",
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster", "ALIYUN::CS::KubernetesCluster"],
}

# Check if cluster is multi-zone
is_multi_zone(resource) if {
	count(object.get(resource.Properties, "VSwitchIds", [])) >= 3
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ZoneIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
