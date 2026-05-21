package infraguard.rules.terraform.rds_instances_in_vpc

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-instances-in-vpc",
	"severity": "high",
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
		"en": "Set vswitch_id for the RDS instance to deploy it within a VPC.",
		"zh": "为 RDS 实例设置 vswitch_id 以将其部署在 VPC 内。",
		"ja": "RDS インスタンスの vswitch_id を設定して VPC 内に展開します。",
		"de": "Setzen Sie vswitch_id für die RDS-Instanz, um sie innerhalb eines VPC bereitzustellen.",
		"es": "Establezca vswitch_id para la instancia RDS para implementarla dentro de un VPC.",
		"fr": "Définissez vswitch_id pour l'instance RDS pour la déployer dans un VPC.",
		"pt": "Defina vswitch_id para a instância RDS para implantá-la dentro de um VPC."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	vswitch_id := tf.get_attribute(resource, "vswitch_id", "")
	vswitch_id == ""
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
