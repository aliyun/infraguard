package infraguard.rules.aliyun.privatelink_server_endpoint_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "privatelink-server-endpoint-multi-zone",
	"severity": "medium",
	"name": {
		"en": "PrivateLink VPC Endpoint Service Multi-Zone Deployment",
		"zh": "PrivateLink 服务终端节点部署在多可用区",
		"ja": "PrivateLink VPC エンドポイントサービスのマルチゾーン展開",
		"de": "PrivateLink VPC-Endpunkt-Service Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona del Servicio de Punto de Extremo VPC PrivateLink",
		"fr": "Déploiement Multi-Zone du Service de Point de Terminaison VPC PrivateLink",
		"pt": "Implantação Multi-Zona do Serviço de Endpoint VPC PrivateLink"
	},
	"description": {
		"en": "PrivateLink VPC endpoint services should have resources deployed across multiple availability zones for high availability.",
		"zh": "PrivateLink 服务终端节点应将资源部署在多个可用区以实现高可用性。",
		"ja": "PrivateLink VPC エンドポイントサービスは、高可用性のためにリソースを複数の可用性ゾーンに展開する必要があります。",
		"de": "PrivateLink VPC-Endpunkt-Services sollten Ressourcen für hohe Verfügbarkeit über mehrere Verfügbarkeitszonen hinweg bereitgestellt haben.",
		"es": "Los servicios de punto de extremo VPC PrivateLink deben tener recursos desplegados en múltiples zonas de disponibilidad para alta disponibilidad.",
		"fr": "Les services de point de terminaison VPC PrivateLink doivent avoir des ressources déployées sur plusieurs zones de disponibilité pour une haute disponibilité.",
		"pt": "Os serviços de endpoint VPC PrivateLink devem ter recursos implantados em múltiplas zonas de disponibilidade para alta disponibilidade."
	},
	"reason": {
		"en": "The PrivateLink VPC endpoint service does not have resources in multiple zones, which may affect availability.",
		"zh": "PrivateLink 服务终端节点没有在多个可用区部署资源，可能影响可用性。",
		"ja": "PrivateLink VPC エンドポイントサービスに複数のゾーンにリソースがないため、可用性に影響を与える可能性があります。",
		"de": "Der PrivateLink VPC-Endpunkt-Service hat keine Ressourcen in mehreren Zonen, was die Verfügbarkeit beeinträchtigen kann.",
		"es": "El servicio de punto de extremo VPC PrivateLink no tiene recursos en múltiples zonas, lo que puede afectar la disponibilidad.",
		"fr": "Le service de point de terminaison VPC PrivateLink n'a pas de ressources dans plusieurs zones, ce qui peut affecter la disponibilité.",
		"pt": "O serviço de endpoint VPC PrivateLink não tem recursos em múltiplas zonas, o que pode afetar a disponibilidade."
	},
	"recommendation": {
		"en": "Deploy service resources across at least two availability zones by specifying multiple entries with different ZoneIds in the Resource property.",
		"zh": "通过在 Resource 属性中指定具有不同 ZoneId 的多个条目，将服务资源部署在至少两个可用区。",
		"ja": "Resource プロパティで異なる ZoneId を持つ複数のエントリを指定して、サービスリソースを少なくとも 2 つの可用性ゾーンに展開します。",
		"de": "Stellen Sie Service-Ressourcen über mindestens zwei Verfügbarkeitszonen bereit, indem Sie mehrere Einträge mit unterschiedlichen ZoneIds in der Resource-Eigenschaft angeben.",
		"es": "Despliegue recursos del servicio en al menos dos zonas de disponibilidad especificando múltiples entradas con diferentes ZoneIds en la propiedad Resource.",
		"fr": "Déployez les ressources du service sur au moins deux zones de disponibilité en spécifiant plusieurs entrées avec différents ZoneIds dans la propriété Resource.",
		"pt": "Implante recursos do serviço em pelo menos duas zonas de disponibilidade especificando múltiplas entradas com diferentes ZoneIds na propriedade Resource."
	},
	"resource_types": ["ALIYUN::PrivateLink::VpcEndpointService"]
}

# Get unique zone IDs from resources
get_unique_zones(resource) := zones if {
	helpers.has_property(resource, "Resource")
	resources := resource.Properties.Resource
	zones := {r.ZoneId | some r in resources}
}

# Check if service has resources in multiple zones
has_multiple_zones(resource) if {
	zones := get_unique_zones(resource)
	count(zones) >= 2
}

# Deny rule: PrivateLink VPC endpoint services should have resources in multiple zones
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::PrivateLink::VpcEndpointService")
	not has_multiple_zones(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Resource"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
