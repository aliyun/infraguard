package infraguard.rules.aliyun.rds_instances_in_vpc

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rds-instances-in-vpc",
	"severity": "medium",
	"name": {
		"en": "RDS Instance in VPC",
		"zh": "RDS 实例在 VPC 内",
		"ja": "VPC 内の RDS インスタンス",
		"de": "RDS-Instanz in VPC",
		"es": "Instancia RDS en VPC",
		"fr": "Instance RDS dans VPC",
		"pt": "Instância RDS em VPC"
	},
	"description": {
		"en": "Ensures that the RDS instance is deployed within a VPC.",
		"zh": "确保 RDS 实例部署在 VPC 内。",
		"ja": "RDS インスタンスが VPC 内に展開されていることを確認します。",
		"de": "Stellt sicher, dass die RDS-Instanz innerhalb eines VPC bereitgestellt wird.",
		"es": "Garantiza que la instancia RDS se implemente dentro de un VPC.",
		"fr": "Garantit que l'instance RDS est déployée dans un VPC.",
		"pt": "Garante que a instância RDS seja implantada dentro de um VPC."
	},
	"reason": {
		"en": "Deploying RDS in a VPC provides better network isolation and security.",
		"zh": "在 VPC 中部署 RDS 可提供更好的网络隔离和安全性。",
		"ja": "RDS を VPC に展開することで、より優れたネットワーク分離とセキュリティが提供されます。",
		"de": "Die Bereitstellung von RDS in einem VPC bietet bessere Netzwerkisolation und Sicherheit.",
		"es": "Implementar RDS en un VPC proporciona mejor aislamiento de red y seguridad.",
		"fr": "Déployer RDS dans un VPC offre un meilleur isolement réseau et une meilleure sécurité.",
		"pt": "Implantar RDS em um VPC fornece melhor isolamento de rede e segurança."
	},
	"recommendation": {
		"en": "Deploy the RDS instance within a VPC.",
		"zh": "将 RDS 实例部署在 VPC 内。",
		"ja": "RDS インスタンスを VPC 内に展開します。",
		"de": "Stellen Sie die RDS-Instanz innerhalb eines VPC bereit.",
		"es": "Implemente la instancia RDS dentro de un VPC.",
		"fr": "Déployez l'instance RDS dans un VPC.",
		"pt": "Implante a instância RDS dentro de um VPC."
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not helpers.has_property(resource, "VPCId")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VPCId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
