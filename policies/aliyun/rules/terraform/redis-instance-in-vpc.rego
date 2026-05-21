package infraguard.rules.terraform.redis_instance_in_vpc

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-instance-in-vpc",
	"severity": "medium",
	"name": {
		"en": "Redis Instance in VPC",
		"zh": "使用专有网络类型的 Redis 实例",
		"ja": "VPC 内の Redis インスタンス",
		"de": "Redis-Instanz in VPC",
		"es": "Instancia Redis en VPC",
		"fr": "Instance Redis dans VPC",
		"pt": "Instância Redis em VPC"
	},
	"description": {
		"en": "Ensures Redis instance is deployed in a VPC.",
		"zh": "确保 Redis 实例部署在专有网络中。",
		"ja": "Redis インスタンスが VPC に展開されていることを確認します。",
		"de": "Stellt sicher, dass die Redis-Instanz in einem VPC bereitgestellt wird.",
		"es": "Garantiza que la instancia Redis se despliegue en una VPC.",
		"fr": "Garantit que l'instance Redis est déployée dans un VPC.",
		"pt": "Garante que a instância Redis seja implantada em uma VPC."
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
		"en": "Deploy Redis instance in a VPC by setting vswitch_id.",
		"zh": "通过设置 vswitch_id 将 Redis 实例部署在 VPC 中。",
		"ja": "vswitch_id を設定して Redis インスタンスを VPC に展開します。",
		"de": "Stellen Sie die Redis-Instanz in einem VPC bereit, indem Sie vswitch_id setzen.",
		"es": "Despliegue la instancia Redis en una VPC configurando vswitch_id.",
		"fr": "Déployez l'instance Redis dans un VPC en définissant vswitch_id.",
		"pt": "Implante a instância Redis em uma VPC configurando vswitch_id."
	},
	"resource_types": ["alicloud_kvstore_instance"],
	"iac_type": "terraform"
}

is_in_vpc(resource) if {
	vswitch_id := tf.get_attribute(resource, "vswitch_id", "")
	not tf.is_unknown(vswitch_id)
	vswitch_id != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	not is_in_vpc(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_kvstore_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
