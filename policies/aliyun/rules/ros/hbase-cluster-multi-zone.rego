package infraguard.rules.aliyun.hbase_cluster_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "hbase-cluster-multi-zone",
	"severity": "medium",
	"name": {
		"en": "HBase Cluster Multi-Zone Deployment",
		"zh": "使用多可用区的 HBase 集群",
		"ja": "HBase クラスターマルチゾーン展開",
		"de": "HBase-Cluster Multi-Zonen-Bereitstellung",
		"es": "Implementación Multi-Zona del Clúster HBase",
		"fr": "Déploiement Multi-Zone du Cluster HBase",
		"pt": "Implantação Multi-Zona do Cluster HBase"
	},
	"description": {
		"en": "HBase clusters should be deployed in cluster mode with at least 2 nodes for high availability.",
		"zh": "使用多可用区的 HBase 集群，视为合规。",
		"ja": "HBase クラスターは高可用性のために少なくとも 2 つのノードでクラスターモードに展開する必要があります。",
		"de": "HBase-Cluster sollten im Clustermodus mit mindestens 2 Knoten für Hochverfügbarkeit bereitgestellt werden.",
		"es": "Los clústeres HBase deben implementarse en modo clúster con al menos 2 nodos para alta disponibilidad.",
		"fr": "Les clusters HBase doivent être déployés en mode cluster avec au moins 2 nœuds pour une haute disponibilité.",
		"pt": "Os clusters HBase devem ser implantados em modo cluster com pelo menos 2 nós para alta disponibilidade."
	},
	"reason": {
		"en": "The HBase cluster is deployed in single-node mode, which does not provide high availability.",
		"zh": "HBase 集群部署在单节点模式，不提供高可用性。",
		"ja": "HBase クラスターがシングルノードモードで展開されているため、高可用性が提供されません。",
		"de": "Der HBase-Cluster wird im Einzelknotenmodus bereitgestellt, was keine Hochverfügbarkeit bietet.",
		"es": "El clúster HBase se implementa en modo de nodo único, que no proporciona alta disponibilidad.",
		"fr": "Le cluster HBase est déployé en mode nœud unique, ce qui ne fournit pas de haute disponibilité.",
		"pt": "O cluster HBase é implantado em modo de nó único, que não fornece alta disponibilidade."
	},
	"recommendation": {
		"en": "Deploy HBase cluster in cluster mode by setting NodeCount to at least 2 for high availability.",
		"zh": "通过将 NodeCount 设置为至少 2 来部署 HBase 集群的集群模式，以实现高可用性。",
		"ja": "高可用性のために NodeCount を少なくとも 2 に設定して、HBase クラスターをクラスターモードで展開します。",
		"de": "Stellen Sie den HBase-Cluster im Clustermodus bereit, indem Sie NodeCount auf mindestens 2 für Hochverfügbarkeit setzen.",
		"es": "Implemente el clúster HBase en modo clúster estableciendo NodeCount en al menos 2 para alta disponibilidad.",
		"fr": "Déployez le cluster HBase en mode cluster en définissant NodeCount sur au moins 2 pour une haute disponibilité.",
		"pt": "Implante o cluster HBase em modo cluster definindo NodeCount para pelo menos 2 para alta disponibilidade."
	},
	"resource_types": ["ALIYUN::HBase::Cluster"]
}

# Check if cluster is in cluster mode (at least 2 nodes)
is_cluster_mode(resource) if {
	node_count := resource.Properties.NodeCount
	node_count >= 2
}

# Deny rule: HBase clusters should be in cluster mode
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::HBase::Cluster")
	not is_cluster_mode(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "NodeCount"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
