package infraguard.rules.aliyun.mse_cluster_architecture_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mse-cluster-architecture-check",
	"severity": "high",
	"name": {
		"en": "MSE Cluster Has Multiple Nodes",
		"zh": "MSE 注册配置中心多节点检测",
		"ja": "MSE クラスターに複数のノードがある",
		"de": "MSE-Cluster hat mehrere Knoten",
		"es": "Clúster MSE Tiene Múltiples Nodos",
		"fr": "Le Cluster MSE a Plusieurs Nœuds",
		"pt": "Cluster MSE Tem Múltiplos Nós"
	},
	"description": {
		"en": "Ensures that MSE (Microservice Engine) clusters have more than 3 nodes for high availability.",
		"zh": "确保 MSE（微服务引擎）集群具有超过 3 个节点以实现高可用性。",
		"ja": "MSE（マイクロサービスエンジン）クラスターが高可用性のために3つ以上のノードを持つことを確認します。",
		"de": "Stellt sicher, dass MSE (Microservice Engine)-Cluster mehr als 3 Knoten für hohe Verfügbarkeit haben.",
		"es": "Garantiza que los clústeres MSE (Motor de Microservicios) tengan más de 3 nodos para alta disponibilidad.",
		"fr": "Garantit que les clusters MSE (Moteur de Microservices) ont plus de 3 nœuds pour une haute disponibilité.",
		"pt": "Garante que os clusters MSE (Motor de Microserviços) tenham mais de 3 nós para alta disponibilidade."
	},
	"reason": {
		"en": "Clusters with 3 or fewer nodes may not provide adequate high availability.",
		"zh": "3 个或更少节点的集群可能无法提供足够的高可用性。",
		"ja": "3つ以下のノードを持つクラスターは、十分な高可用性を提供できない可能性があります。",
		"de": "Cluster mit 3 oder weniger Knoten bieten möglicherweise keine ausreichende hohe Verfügbarkeit.",
		"es": "Los clústeres con 3 o menos nodos pueden no proporcionar alta disponibilidad adecuada.",
		"fr": "Les clusters avec 3 nœuds ou moins peuvent ne pas fournir une haute disponibilité adéquate.",
		"pt": "Clusters com 3 ou menos nós podem não fornecer alta disponibilidade adequada."
	},
	"recommendation": {
		"en": "Configure the MSE cluster with more than 3 nodes.",
		"zh": "将 MSE 集群配置为超过 3 个节点。",
		"ja": "MSE クラスターを3つ以上のノードで設定します。",
		"de": "Konfigurieren Sie den MSE-Cluster mit mehr als 3 Knoten.",
		"es": "Configure el clúster MSE con más de 3 nodos.",
		"fr": "Configurez le cluster MSE avec plus de 3 nœuds.",
		"pt": "Configure o cluster MSE com mais de 3 nós."
	},
	"resource_types": ["ALIYUN::MSE::Cluster"]
}

# Get node count from cluster
get_node_count(resource) := node_count if {
	# Try Nodes array first
	nodes := helpers.get_property(resource, "Nodes", [])
	count(nodes) > 0
	node_count := count(nodes)
} else := node_count if {
	# Fall back to InstanceCount
	instance_count := helpers.get_property(resource, "InstanceCount", 0)
	node_count := instance_count
}

# Check if cluster has more than 3 nodes
has_multi_nodes(resource) if {
	get_node_count(resource) > 3
}

is_compliant(resource) if {
	has_multi_nodes(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Cluster")
	not has_multi_nodes(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Nodes"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
