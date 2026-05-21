package infraguard.rules.terraform.polardb_dbcluster_in_vpc

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "polardb-dbcluster-in-vpc",
	"severity": "medium",
	"name": {
		"en": "PolarDB Cluster in VPC",
		"zh": "推荐使用专有网络类型的 PolarDB 实例",
		"ja": "VPC 内の PolarDB クラスター",
		"de": "PolarDB-Cluster in VPC",
		"es": "Clúster PolarDB en VPC",
		"fr": "Cluster PolarDB dans VPC",
		"pt": "Cluster PolarDB em VPC"
	},
	"description": {
		"en": "Ensures PolarDB cluster is deployed in a VPC by setting vswitch_id.",
		"zh": "确保 PolarDB 实例通过设置 vswitch_id 部署在专有网络中。",
		"ja": "vswitch_id を設定して PolarDB クラスターが VPC に展開されていることを確認します。",
		"de": "Stellt sicher, dass der PolarDB-Cluster durch Setzen von vswitch_id in einem VPC bereitgestellt wird.",
		"es": "Garantiza que el clúster PolarDB se despliegue en una VPC configurando vswitch_id.",
		"fr": "Garantit que le cluster PolarDB est déployé dans un VPC en définissant vswitch_id.",
		"pt": "Garante que o cluster PolarDB seja implantado em uma VPC definindo vswitch_id."
	},
	"reason": {
		"en": "VPC provides better network isolation and security.",
		"zh": "VPC 提供更好的网络隔离和安全性。",
		"ja": "VPC はより優れたネットワーク分離とセキュリティを提供します。",
		"de": "VPC bietet bessere Netzwerkisolation und Sicherheit.",
		"es": "VPC proporciona mejor aislamiento de red y seguridad.",
		"fr": "VPC offre une meilleure isolation réseau et sécurité.",
		"pt": "VPC fornece melhor isolamento de rede e segurança."
	},
	"recommendation": {
		"en": "Set vswitch_id for the PolarDB cluster to deploy it within a VPC.",
		"zh": "为 PolarDB 集群设置 vswitch_id 以将其部署在 VPC 内。",
		"ja": "PolarDB クラスターの vswitch_id を設定して VPC 内に展開します。",
		"de": "Setzen Sie vswitch_id für den PolarDB-Cluster, um ihn innerhalb eines VPC bereitzustellen.",
		"es": "Configure vswitch_id para el clúster PolarDB para implementarlo dentro de una VPC.",
		"fr": "Définissez vswitch_id pour le cluster PolarDB pour le déployer dans un VPC.",
		"pt": "Defina vswitch_id para o cluster PolarDB para implantá-lo dentro de uma VPC."
	},
	"resource_types": ["alicloud_polardb_cluster"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_polardb_cluster")
	vswitch_id := tf.get_attribute(resource, "vswitch_id", "")
	vswitch_id == ""
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_polardb_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
