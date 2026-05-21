package infraguard.rules.terraform.acs_cluster_node_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "acs-cluster-node-multi-zone",
	"severity": "high",
	"name": {
		"en": "ACS Cluster Node Multi-Zone Deployment",
		"zh": "使用区域级多可用区 ACS 集群",
		"ja": "ACS クラスターノードのマルチゾーン展開",
		"de": "ACS-Cluster-Knoten Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Nodos de Clúster ACS",
		"fr": "Déploiement Multi-Zone des Nœuds du Cluster ACS",
		"pt": "Implantação Multi-Zona de Nós do Cluster ACS"
	},
	"description": {
		"en": "The ACS cluster nodes should be distributed across 3 or more availability zones for high availability.",
		"zh": "使用区域级 ACS 集群，节点分布在 3 个及以上可用区，视为合规。",
		"ja": "ACS クラスターノードは高可用性のために 3 つ以上の可用性ゾーンに分散する必要があります。",
		"de": "Die ACS-Cluster-Knoten sollten für hohe Verfügbarkeit über 3 oder mehr Verfügbarkeitszonen verteilt werden.",
		"es": "Los nodos del clúster ACS deben distribuirse en 3 o más zonas de disponibilidad para alta disponibilidad.",
		"fr": "Les nœuds du cluster ACS doivent être distribués sur 3 zones de disponibilité ou plus pour une haute disponibilité.",
		"pt": "Os nós do cluster ACS devem ser distribuídos em 3 ou mais zonas de disponibilidade para alta disponibilidade."
	},
	"reason": {
		"en": "The ACS cluster nodes are not distributed across 3 or more availability zones.",
		"zh": "ACS 集群节点未分布在 3 个及以上可用区。",
		"ja": "ACS クラスターノードが 3 つ以上の可用性ゾーンに分散されていません。",
		"de": "Die ACS-Cluster-Knoten sind nicht über 3 oder mehr Verfügbarkeitszonen verteilt.",
		"es": "Los nodos del clúster ACS no están distribuidos en 3 o más zonas de disponibilidad.",
		"fr": "Les nœuds du cluster ACS ne sont pas distribués sur 3 zones de disponibilité ou plus.",
		"pt": "Os nós do cluster ACS não estão distribuídos em 3 ou mais zonas de disponibilidade."
	},
	"recommendation": {
		"en": "Configure the cluster to use at least 3 availability zones by specifying multiple ZoneIds or VSwitchIds.",
		"zh": "通过指定多个 ZoneIds 或 VSwitchIds，将集群配置为使用至少 3 个可用区。",
		"ja": "複数の ZoneIds または VSwitchIds を指定して、クラスターを少なくとも 3 つの可用性ゾーンを使用するように設定します。",
		"de": "Konfigurieren Sie den Cluster so, dass er mindestens 3 Verfügbarkeitszonen verwendet, indem Sie mehrere ZoneIds oder VSwitchIds angeben.",
		"es": "Configure el clúster para usar al menos 3 zonas de disponibilidad especificando múltiples ZoneIds o VSwitchIds.",
		"fr": "Configurez le cluster pour utiliser au moins 3 zones de disponibilité en spécifiant plusieurs ZoneIds ou VSwitchIds.",
		"pt": "Configure o cluster para usar pelo menos 3 zonas de disponibilidade especificando múltiplos ZoneIds ou VSwitchIds."
	},
	"resource_types": ["alicloud_cs_managed_kubernetes"],
	"iac_type": "terraform"
}

# Check if cluster has multi-zone deployment via worker_vswitch_ids
is_multi_zone(resource) if {
	vswitches := tf.get_attribute(resource, "worker_vswitch_ids", [])
	not tf.is_unknown(vswitches)
	count(vswitches) >= 3
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_cs_managed_kubernetes")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_cs_managed_kubernetes.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
