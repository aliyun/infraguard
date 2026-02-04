package infraguard.rules.aliyun.lindorm_instance_in_vpc

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "lindorm-instance-in-vpc",
	"name": {
		"en": "Lindorm in VPC Check",
		"zh": "Lindorm 实例强制 VPC 部署",
		"ja": "Lindorm の VPC チェック",
		"de": "Lindorm in VPC-Prüfung",
		"es": "Verificación de Lindorm en VPC",
		"fr": "Vérification de Lindorm dans VPC",
		"pt": "Verificação de Lindorm em VPC"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Lindorm instances are deployed within a VPC.",
		"zh": "确保 Lindorm 实例部署在 VPC 内。",
		"ja": "Lindorm インスタンスが VPC 内に展開されていることを確認します。",
		"de": "Stellt sicher, dass Lindorm-Instanzen innerhalb eines VPC bereitgestellt werden.",
		"es": "Garantiza que las instancias Lindorm se desplieguen dentro de una VPC.",
		"fr": "Garantit que les instances Lindorm sont déployées dans un VPC.",
		"pt": "Garante que as instâncias Lindorm sejam implantadas dentro de uma VPC."
	},
	"reason": {
		"en": "Deploying in a VPC provides better network isolation and security.",
		"zh": "在 VPC 中部署可提供更好的网络隔离和安全性。",
		"ja": "VPC に展開することで、より優れたネットワーク分離とセキュリティが提供されます。",
		"de": "Die Bereitstellung in einem VPC bietet bessere Netzwerkisolation und Sicherheit.",
		"es": "Desplegar en una VPC proporciona mejor aislamiento de red y seguridad.",
		"fr": "Le déploiement dans un VPC offre une meilleure isolation réseau et sécurité.",
		"pt": "Implantar em uma VPC fornece melhor isolamento de rede e segurança."
	},
	"recommendation": {
		"en": "Create Lindorm instances within a VPC.",
		"zh": "在 VPC 内创建 Lindorm 实例。",
		"ja": "VPC 内に Lindorm インスタンスを作成します。",
		"de": "Erstellen Sie Lindorm-Instanzen innerhalb eines VPC.",
		"es": "Cree instancias Lindorm dentro de una VPC.",
		"fr": "Créez des instances Lindorm dans un VPC.",
		"pt": "Crie instâncias Lindorm dentro de uma VPC."
	},
	"resource_types": ["ALIYUN::Lindorm::Instance"],
}

is_compliant(resource) if {
	vpc_id := helpers.get_property(resource, "VpcId", "")
	vpc_id != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::Lindorm::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
