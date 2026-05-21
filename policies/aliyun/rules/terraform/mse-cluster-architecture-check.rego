package infraguard.rules.terraform.mse_cluster_architecture_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "MSE cluster instance_count should be greater than 3 for high availability.",
		"zh": "MSE 集群的 instance_count 应大于 3 以实现高可用。",
		"ja": "MSE（マイクロサービスエンジン）クラスターが高可用性のために3つ以上のノードを持つことを確認します。",
		"de": "Stellt sicher, dass MSE (Microservice Engine)-Cluster mehr als 3 Knoten für hohe Verfügbarkeit haben.",
		"es": "Garantiza que los clústeres MSE (Motor de Microservicios) tengan más de 3 nodos para alta disponibilidad.",
		"fr": "Garantit que les clusters MSE (Moteur de Microservices) ont plus de 3 nœuds pour une haute disponibilité.",
		"pt": "Garante que os clusters MSE (Motor de Microserviços) tenham mais de 3 nós para alta disponibilidade."
	},
	"reason": {
		"en": "The MSE cluster instance_count is not greater than 3.",
		"zh": "MSE 集群的 instance_count 未大于 3。",
		"ja": "3つ以下のノードを持つクラスターは、十分な高可用性を提供できない可能性があります。",
		"de": "Cluster mit 3 oder weniger Knoten bieten möglicherweise keine ausreichende hohe Verfügbarkeit.",
		"es": "Los clústeres con 3 o menos nodos pueden no proporcionar alta disponibilidad adecuada.",
		"fr": "Les clusters avec 3 nœuds ou moins peuvent ne pas fournir une haute disponibilité adéquate.",
		"pt": "Clusters com 3 ou menos nós podem não fornecer alta disponibilidade adequada."
	},
	"recommendation": {
		"en": "Set instance_count to greater than 3 for high availability.",
		"zh": "将 instance_count 设置为大于 3 以实现高可用。",
		"ja": "MSE クラスターを3つ以上のノードで設定します。",
		"de": "Konfigurieren Sie den MSE-Cluster mit mehr als 3 Knoten.",
		"es": "Configure el clúster MSE con más de 3 nodos.",
		"fr": "Configurez le cluster MSE avec plus de 3 nœuds.",
		"pt": "Configure o cluster MSE com mais de 3 nós."
	},
	"resource_types": ["alicloud_mse_cluster"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mse_cluster")
	instance_count := tf.get_attribute(resource, "instance_count", 0)
	instance_count <= 3
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mse_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
