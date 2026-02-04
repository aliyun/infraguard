package infraguard.rules.aliyun.ecs_launch_template_network_type_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-launch-template-network-type-check",
	"name": {
		"en": "ECS launch template uses VPC network type",
		"zh": "ECS 启动模版配置不应设置公网访问",
		"ja": "ECS 起動テンプレートが VPC ネットワークタイプを使用",
		"de": "ECS-Startvorlage verwendet VPC-Netzwerktyp",
		"es": "La plantilla de inicio de ECS usa tipo de red VPC",
		"fr": "Le modèle de lancement ECS utilise le type de réseau VPC",
		"pt": "O modelo de inicialização do ECS usa tipo de rede VPC"
	},
	"description": {
		"en": "ECS launch template versions have network type set to VPC, considered compliant. Classic network type is not recommended for production environments.",
		"zh": "ECS 启动模版版本中网络类型为 VPC 类型，视为合规。",
		"ja": "ECS 起動テンプレートバージョンでネットワークタイプが VPC に設定されている場合、準拠と見なされます。クラシックネットワークタイプは本番環境には推奨されません。",
		"de": "ECS-Startvorlagenversionen haben den Netzwerktyp auf VPC gesetzt, was als konform gilt. Der klassische Netzwerktyp wird für Produktionsumgebungen nicht empfohlen.",
		"es": "Las versiones de plantilla de inicio de ECS tienen el tipo de red configurado como VPC, considerado conforme. El tipo de red clásica no se recomienda para entornos de producción.",
		"fr": "Les versions de modèle de lancement ECS ont le type de réseau défini sur VPC, considéré comme conforme. Le type de réseau classique n'est pas recommandé pour les environnements de production.",
		"pt": "As versões do modelo de inicialização do ECS têm o tipo de rede definido como VPC, considerado em conformidade. O tipo de rede clássica não é recomendado para ambientes de produção."
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::LaunchTemplate"],
	"reason": {
		"en": "ECS launch template is configured with classic network type",
		"zh": "ECS 启动模板配置了经典网络类型",
		"ja": "ECS 起動テンプレートがクラシックネットワークタイプで設定されています",
		"de": "ECS-Startvorlage ist mit klassischem Netzwerktyp konfiguriert",
		"es": "La plantilla de inicio de ECS está configurada con tipo de red clásica",
		"fr": "Le modèle de lancement ECS est configuré avec le type de réseau classique",
		"pt": "O modelo de inicialização do ECS está configurado com tipo de rede clássica"
	},
	"recommendation": {
		"en": "Use VPC network type in launch templates for better network isolation",
		"zh": "在启动模板中使用 VPC 网络类型以获得更好的网络隔离",
		"ja": "より良いネットワーク分離のために起動テンプレートで VPC ネットワークタイプを使用します",
		"de": "Verwenden Sie den VPC-Netzwerktyp in Startvorlagen für bessere Netzwerkisolation",
		"es": "Use el tipo de red VPC en las plantillas de inicio para mejor aislamiento de red",
		"fr": "Utilisez le type de réseau VPC dans les modèles de lancement pour une meilleure isolation réseau",
		"pt": "Use o tipo de rede VPC nos modelos de inicialização para melhor isolamento de rede"
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::LaunchTemplate")

	# Check network type
	network_type := helpers.get_property(resource, "NetworkType", "")

	# Classic network is not recommended
	network_type == "classic"

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "NetworkType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
