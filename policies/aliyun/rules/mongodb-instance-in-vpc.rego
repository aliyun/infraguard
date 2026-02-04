package infraguard.rules.aliyun.mongodb_instance_in_vpc

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mongodb-instance-in-vpc",
	"name": {
		"en": "MongoDB Instance Uses VPC Network",
		"zh": "使用专有网络类型的 MongoDB 实例",
		"ja": "MongoDB インスタンスが VPC ネットワークを使用",
		"de": "MongoDB-Instanz verwendet VPC-Netzwerk",
		"es": "La Instancia MongoDB Usa Red VPC",
		"fr": "L'Instance MongoDB Utilise le Réseau VPC",
		"pt": "A Instância MongoDB Usa Rede VPC"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures MongoDB instances are deployed in a Virtual Private Cloud (VPC) network.",
		"zh": "确保 MongoDB 实例部署在专有网络（VPC）中。",
		"ja": "MongoDB インスタンスが仮想プライベートクラウド（VPC）ネットワークに展開されていることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen in einem Virtual Private Cloud (VPC)-Netzwerk bereitgestellt werden.",
		"es": "Garantiza que las instancias MongoDB se desplieguen en una red de Nube Privada Virtual (VPC).",
		"fr": "Garantit que les instances MongoDB sont déployées dans un réseau de Cloud Privé Virtuel (VPC).",
		"pt": "Garante que as instâncias MongoDB sejam implantadas em uma rede de Nuvem Privada Virtual (VPC)."
	},
	"reason": {
		"en": "VPC provides network isolation and better security compared to the classic network.",
		"zh": "与经典网络相比，VPC 提供网络隔离和更好的安全性。",
		"ja": "VPC はクラシックネットワークと比較して、ネットワーク分離とより優れたセキュリティを提供します。",
		"de": "VPC bietet Netzwerkisolation und bessere Sicherheit im Vergleich zum klassischen Netzwerk.",
		"es": "VPC proporciona aislamiento de red y mejor seguridad en comparación con la red clásica.",
		"fr": "VPC offre une isolation réseau et une meilleure sécurité par rapport au réseau classique.",
		"pt": "VPC fornece isolamento de rede e melhor segurança em comparação com a rede clássica."
	},
	"recommendation": {
		"en": "Deploy the MongoDB instance in a VPC network.",
		"zh": "将 MongoDB 实例部署在专有网络中。",
		"ja": "VPC ネットワークに MongoDB インスタンスを展開します。",
		"de": "Stellen Sie die MongoDB-Instanz in einem VPC-Netzwerk bereit.",
		"es": "Despliegue la instancia MongoDB en una red VPC.",
		"fr": "Déployez l'instance MongoDB dans un réseau VPC.",
		"pt": "Implante a instância MongoDB em uma rede VPC."
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

# Check if instance is in VPC
is_compliant(resource) if {
	vpc_id := helpers.get_property(resource, "VpcId", "")
	vpc_id != ""
}

is_compliant(resource) if {
	network_type := helpers.get_property(resource, "NetworkType", "")
	network_type == "VPC"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
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
