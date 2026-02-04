package infraguard.rules.aliyun.ecs_instances_in_vpc

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-instances-in-vpc",
	"severity": "medium",
	"name": {
		"en": "ECS Instances in VPC",
		"zh": "使用专有网络类型的 ECS 实例",
		"ja": "VPC 内の ECS インスタンス",
		"de": "ECS-Instanzen in VPC",
		"es": "Instancias ECS en VPC",
		"fr": "Instances ECS dans le VPC",
		"pt": "Instâncias ECS em VPC"
	},
	"description": {
		"en": "ECS instances should be deployed in VPC (Virtual Private Cloud) networks rather than classic networks. VPC provides better network isolation, security, and flexibility.",
		"zh": "ECS 实例应部署在专有网络(VPC)而非经典网络中。VPC 提供更好的网络隔离、安全性和灵活性。",
		"ja": "ECS インスタンスは、クラシックネットワークではなく VPC（Virtual Private Cloud）ネットワークに展開する必要があります。VPC はより優れたネットワーク分離、セキュリティ、柔軟性を提供します。",
		"de": "ECS-Instanzen sollten in VPC (Virtual Private Cloud) Netzwerken und nicht in klassischen Netzwerken bereitgestellt werden. VPC bietet bessere Netzwerkisolation, Sicherheit und Flexibilität.",
		"es": "Las instancias ECS deben implementarse en redes VPC (Virtual Private Cloud) en lugar de redes clásicas. VPC proporciona mejor aislamiento de red, seguridad y flexibilidad.",
		"fr": "Les instances ECS doivent être déployées dans des réseaux VPC (Virtual Private Cloud) plutôt que dans des réseaux classiques. VPC offre une meilleure isolation réseau, sécurité et flexibilité.",
		"pt": "Instâncias ECS devem ser implantadas em redes VPC (Virtual Private Cloud) em vez de redes clássicas. O VPC fornece melhor isolamento de rede, segurança e flexibilidade."
	},
	"reason": {
		"en": "The ECS instance is not deployed in a VPC, which may result in insufficient network isolation and security.",
		"zh": "ECS 实例未部署在 VPC 中，可能导致网络隔离和安全性不足。",
		"ja": "ECS インスタンスが VPC に展開されていないため、ネットワーク分離とセキュリティが不十分になる可能性があります。",
		"de": "Die ECS-Instanz ist nicht in einem VPC bereitgestellt, was zu unzureichender Netzwerkisolation und Sicherheit führen kann.",
		"es": "La instancia ECS no está implementada en un VPC, lo que puede resultar en aislamiento de red y seguridad insuficientes.",
		"fr": "L'instance ECS n'est pas déployée dans un VPC, ce qui peut entraîner un isolement réseau et une sécurité insuffisants.",
		"pt": "A instância ECS não está implantada em um VPC, o que pode resultar em isolamento de rede e segurança insuficientes."
	},
	"recommendation": {
		"en": "Deploy the ECS instance in a VPC by specifying the VpcId and VSwitchId properties.",
		"zh": "通过指定 VpcId 和 VSwitchId 属性，将 ECS 实例部署在 VPC 中。",
		"ja": "VpcId と VSwitchId プロパティを指定して、ECS インスタンスを VPC に展開します。",
		"de": "Stellen Sie die ECS-Instanz in einem VPC bereit, indem Sie die Eigenschaften VpcId und VSwitchId angeben.",
		"es": "Implemente la instancia ECS en un VPC especificando las propiedades VpcId y VSwitchId.",
		"fr": "Déployez l'instance ECS dans un VPC en spécifiant les propriétés VpcId et VSwitchId.",
		"pt": "Implante a instância ECS em um VPC especificando as propriedades VpcId e VSwitchId."
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"]
}

deny contains result if {
	some name, resource in helpers.resources_by_types({"ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"})
	not is_in_vpc(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

is_in_vpc(resource) if {
	helpers.has_property(resource, "VpcId")
	helpers.has_property(resource, "VSwitchId")
}
