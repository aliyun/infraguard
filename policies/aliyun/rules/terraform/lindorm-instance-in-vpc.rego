package infraguard.rules.terraform.lindorm_instance_in_vpc

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "lindorm-instance-in-vpc",
	"severity": "high",
	"name": {
		"en": "Lindorm Instance in VPC",
		"zh": "使用专有网络类型的 Lindorm 实例",
		"ja": "VPC 内の Lindorm インスタンス",
		"de": "Lindorm-Instanz in VPC",
		"es": "Instancia Lindorm en VPC",
		"fr": "Instance Lindorm dans VPC",
		"pt": "Instância Lindorm em VPC"
	},
	"description": {
		"en": "Ensures Lindorm instance is deployed in a VPC.",
		"zh": "确保 Lindorm 实例部署在专有网络中。",
		"ja": "Lindorm インスタンスが VPC に展開されていることを確認します。",
		"de": "Stellt sicher, dass die Lindorm-Instanz in einem VPC bereitgestellt wird.",
		"es": "Garantiza que la instancia Lindorm se despliegue en una VPC.",
		"fr": "Garantit que l'instance Lindorm est déployée dans un VPC.",
		"pt": "Garante que a instância Lindorm seja implantada em uma VPC."
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
		"en": "Deploy Lindorm instance in a VPC by setting vpc_id.",
		"zh": "通过设置 vpc_id 将 Lindorm 实例部署在 VPC 中。",
		"ja": "vpc_id を設定して Lindorm インスタンスを VPC に展開します。",
		"de": "Stellen Sie die Lindorm-Instanz in einem VPC bereit, indem Sie vpc_id setzen.",
		"es": "Despliegue la instancia Lindorm en una VPC configurando vpc_id.",
		"fr": "Déployez l'instance Lindorm dans un VPC en définissant vpc_id.",
		"pt": "Implante a instância Lindorm em uma VPC configurando vpc_id."
	},
	"resource_types": ["alicloud_lindorm_instance"],
	"iac_type": "terraform"
}

is_in_vpc(resource) if {
	vpc_id := tf.get_attribute(resource, "vpc_id", "")
	not tf.is_unknown(vpc_id)
	vpc_id != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_lindorm_instance")
	not is_in_vpc(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_lindorm_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
