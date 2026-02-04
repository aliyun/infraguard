package infraguard.rules.aliyun.hbase_cluster_in_vpc

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "hbase-cluster-in-vpc",
	"name": {
		"en": "HBase Cluster in VPC",
		"zh": "HBase 集群在 VPC 内",
		"ja": "VPC 内の HBase クラスタ",
		"de": "HBase-Cluster im VPC",
		"es": "Clúster HBase en VPC",
		"fr": "Cluster HBase dans VPC",
		"pt": "Cluster HBase em VPC",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the HBase cluster is deployed within a VPC.",
		"zh": "确保 HBase 集群部署在 VPC 内。",
		"ja": "HBase クラスタが VPC 内に展開されていることを確認します。",
		"de": "Stellt sicher, dass der HBase-Cluster innerhalb eines VPC bereitgestellt wird.",
		"es": "Garantiza que el clúster HBase esté desplegado dentro de un VPC.",
		"fr": "Garantit que le cluster HBase est déployé dans un VPC.",
		"pt": "Garante que o cluster HBase esteja implantado dentro de um VPC.",
	},
	"reason": {
		"en": "Deploying HBase in a VPC provides better network isolation and security.",
		"zh": "在 VPC 中部署 HBase 可提供更好的网络隔离和安全性。",
		"ja": "VPC に HBase を展開すると、より優れたネットワーク分離とセキュリティが提供されます。",
		"de": "Die Bereitstellung von HBase in einem VPC bietet bessere Netzwerkisolation und Sicherheit.",
		"es": "Desplegar HBase en un VPC proporciona mejor aislamiento de red y seguridad.",
		"fr": "Déployer HBase dans un VPC offre une meilleure isolation réseau et sécurité.",
		"pt": "Implantar HBase em um VPC fornece melhor isolamento de rede e segurança.",
	},
	"recommendation": {
		"en": "Deploy the HBase cluster within a VPC.",
		"zh": "将 HBase 集群部署在 VPC 内。",
		"ja": "HBase クラスタを VPC 内に展開します。",
		"de": "Stellen Sie den HBase-Cluster innerhalb eines VPC bereit.",
		"es": "Despliegue el clúster HBase dentro de un VPC.",
		"fr": "Déployez le cluster HBase dans un VPC.",
		"pt": "Implante o cluster HBase dentro de um VPC.",
	},
	"resource_types": ["ALIYUN::HBase::Cluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::HBase::Cluster")
	not helpers.has_property(resource, "VpcId")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
