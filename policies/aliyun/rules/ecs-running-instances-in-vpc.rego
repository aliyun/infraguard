package infraguard.rules.aliyun.ecs_running_instances_in_vpc

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-running-instances-in-vpc",
	"name": {
		"en": "Running ECS instances are in VPC",
		"zh": "运行中的 ECS 实例在专有网络",
		"ja": "実行中の ECS インスタンスが VPC 内にある",
		"de": "Laufende ECS-Instanzen sind in VPC",
		"es": "Las Instancias ECS en Ejecución Están en VPC",
		"fr": "Les Instances ECS en Cours d'Exécution Sont dans le VPC",
		"pt": "Instâncias ECS em execução estão em VPC",
	},
	"description": {
		"en": "Running ECS instances are deployed in Virtual Private Cloud (VPC), considered compliant. This provides network isolation and enhanced security.",
		"zh": "阿里云推荐购买的 ECS 放在 VPC 里面。如果 ECS 有归属 VPC 则视为合规。",
		"ja": "実行中の ECS インスタンスが Virtual Private Cloud (VPC) に展開されている場合、準拠と見なされます。これにより、ネットワーク分離とセキュリティの強化が提供されます。",
		"de": "Laufende ECS-Instanzen sind in Virtual Private Cloud (VPC) bereitgestellt, werden als konform betrachtet. Dies bietet Netzwerkisolation und verbesserte Sicherheit.",
		"es": "Las instancias ECS en ejecución se implementan en Virtual Private Cloud (VPC), consideradas conformes. Esto proporciona aislamiento de red y seguridad mejorada.",
		"fr": "Les instances ECS en cours d'exécution sont déployées dans Virtual Private Cloud (VPC), considérées comme conformes. Cela offre un isolement réseau et une sécurité renforcée.",
		"pt": "Instâncias ECS em execução são implantadas em Virtual Private Cloud (VPC), consideradas conformes. Isso fornece isolamento de rede e segurança aprimorada.",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
	"reason": {
		"en": "ECS instance is not deployed in VPC (Classic network)",
		"zh": "ECS 实例未部署在专有网络（经典网络）",
		"ja": "ECS インスタンスが VPC に展開されていない（クラシックネットワーク）",
		"de": "ECS-Instanz ist nicht in VPC bereitgestellt (klassisches Netzwerk)",
		"es": "La instancia ECS no está implementada en VPC (red clásica)",
		"fr": "L'instance ECS n'est pas déployée dans le VPC (réseau classique)",
		"pt": "A instância ECS não está implantada em VPC (rede clássica)",
	},
	"recommendation": {
		"en": "Deploy ECS instances in VPC for network isolation and enhanced security",
		"zh": "将 ECS 实例部署在专有网络中以实现网络隔离和增强安全性",
		"ja": "ネットワーク分離とセキュリティの強化のために、ECS インスタンスを VPC に展開します",
		"de": "Stellen Sie ECS-Instanzen in VPC bereit, um Netzwerkisolation und verbesserte Sicherheit zu erreichen",
		"es": "Implemente instancias ECS en VPC para aislamiento de red y seguridad mejorada",
		"fr": "Déployez les instances ECS dans le VPC pour l'isolement réseau et une sécurité renforcée",
		"pt": "Implante instâncias ECS em VPC para isolamento de rede e segurança aprimorada",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])

	# Check if instance is in classic network (no VPC specified)
	vpc_id := helpers.get_property(resource, "VpcId", "")
	vswitch_id := helpers.get_property(resource, "VSwitchId", "")

	# If neither VpcId nor VSwitchId is specified, it's classic network
	vpc_id == ""
	vswitch_id == ""

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
