package infraguard.rules.aliyun.redis_instance_in_vpc

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "redis-instance-in-vpc",
	"name": {
		"en": "Redis Instance in VPC",
		"zh": "使用专有网络类型的 Redis 实例",
		"ja": "VPC 内の Redis インスタンス",
		"de": "Redis-Instanz in VPC",
		"es": "Instancia Redis en VPC",
		"fr": "Instance Redis dans VPC",
		"pt": "Instância Redis em VPC"
	},
	"severity": "medium",
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
		"en": "Deploy Redis instance in a VPC.",
		"zh": "将 Redis 部署在专有网络中。",
		"ja": "VPC に Redis インスタンスを展開します。",
		"de": "Stellen Sie die Redis-Instanz in einem VPC bereit.",
		"es": "Despliegue la instancia Redis en una VPC.",
		"fr": "Déployez l'instance Redis dans un VPC.",
		"pt": "Implante a instância Redis em uma VPC."
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	vpc_id := helpers.get_property(resource, "VpcId", "")
	vpc_id != ""
}

is_compliant(resource) if {
	vswitch_id := helpers.get_property(resource, "VSwitchId", "")
	vswitch_id != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
