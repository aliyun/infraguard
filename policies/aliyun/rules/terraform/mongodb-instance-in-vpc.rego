package infraguard.rules.terraform.mongodb_instance_in_vpc

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mongodb-instance-in-vpc",
	"severity": "high",
	"name": {
		"en": "MongoDB Instance Deployed in VPC",
		"zh": "MongoDB 实例部署在 VPC 中",
		"ja": "MongoDB インスタンスが VPC ネットワークを使用",
		"de": "MongoDB-Instanz verwendet VPC-Netzwerk",
		"es": "La Instancia MongoDB Usa Red VPC",
		"fr": "L'Instance MongoDB Utilise le Réseau VPC",
		"pt": "A Instância MongoDB Usa Rede VPC"
	},
	"description": {
		"en": "MongoDB instances should be deployed in a VPC for network isolation.",
		"zh": "MongoDB 实例应部署在 VPC 中以实现网络隔离。",
		"ja": "MongoDB インスタンスが仮想プライベートクラウド（VPC）ネットワークに展開されていることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen in einem Virtual Private Cloud (VPC)-Netzwerk bereitgestellt werden.",
		"es": "Garantiza que las instancias MongoDB se desplieguen en una red de Nube Privada Virtual (VPC).",
		"fr": "Garantit que les instances MongoDB sont déployées dans un réseau de Cloud Privé Virtuel (VPC).",
		"pt": "Garante que as instâncias MongoDB sejam implantadas em uma rede de Nuvem Privada Virtual (VPC)."
	},
	"reason": {
		"en": "The MongoDB instance is not deployed in a VPC (no vswitch_id specified).",
		"zh": "MongoDB 实例未部署在 VPC 中（未指定 vswitch_id）。",
		"ja": "VPC はクラシックネットワークと比較して、ネットワーク分離とより優れたセキュリティを提供します。",
		"de": "VPC bietet Netzwerkisolation und bessere Sicherheit im Vergleich zum klassischen Netzwerk.",
		"es": "VPC proporciona aislamiento de red y mejor seguridad en comparación con la red clásica.",
		"fr": "VPC offre une isolation réseau et une meilleure sécurité par rapport au réseau classique.",
		"pt": "VPC fornece isolamento de rede e melhor segurança em comparação com a rede clássica."
	},
	"recommendation": {
		"en": "Specify a vswitch_id to deploy the MongoDB instance in a VPC.",
		"zh": "指定 vswitch_id 以将 MongoDB 实例部署在 VPC 中。",
		"ja": "VPC ネットワークに MongoDB インスタンスを展開します。",
		"de": "Stellen Sie die MongoDB-Instanz in einem VPC-Netzwerk bereit.",
		"es": "Despliegue la instancia MongoDB en una red VPC.",
		"fr": "Déployez l'instance MongoDB dans un réseau VPC.",
		"pt": "Implante a instância MongoDB em uma rede VPC."
	},
	"resource_types": ["alicloud_mongodb_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mongodb_instance")
	tf.get_attribute(resource, "vswitch_id", "") == ""
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mongodb_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
