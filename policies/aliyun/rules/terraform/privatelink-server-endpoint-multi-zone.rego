package infraguard.rules.terraform.privatelink_server_endpoint_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "The PrivateLink VPC endpoint service does not have service_resource_type configured, indicating incomplete service resource configuration.",
		"zh": "PrivateLink 服务终端节点未配置 service_resource_type，表明服务资源配置不完整。",
		"ja": "PrivateLink VPC エンドポイントサービスに service_resource_type が設定されておらず、サービスリソース構成が不完全です。",
		"de": "Der PrivateLink VPC-Endpunkt-Service hat kein service_resource_type konfiguriert, was auf eine unvollständige Service-Ressourcen-Konfiguration hinweist.",
		"es": "El servicio de punto de extremo VPC PrivateLink no tiene service_resource_type configurado, lo que indica una configuración de recursos de servicio incompleta.",
		"fr": "Le service de point de terminaison VPC PrivateLink n'a pas service_resource_type configuré, indiquant une configuration de ressources de service incomplète.",
		"pt": "O serviço de endpoint VPC PrivateLink não tem service_resource_type configurado, indicando configuração de recursos de serviço incompleta."
	},
	"recommendation": {
		"en": "Set the service_resource_type attribute on the alicloud_privatelink_vpc_endpoint_service resource to properly configure service resources.",
		"zh": "在 alicloud_privatelink_vpc_endpoint_service 资源上设置 service_resource_type 属性以正确配置服务资源。",
		"ja": "alicloud_privatelink_vpc_endpoint_service リソースで service_resource_type 属性を設定して、サービスリソースを適切に構成します。",
		"de": "Setzen Sie das service_resource_type-Attribut auf der alicloud_privatelink_vpc_endpoint_service-Ressource, um Service-Ressourcen ordnungsgemäß zu konfigurieren.",
		"es": "Establezca el atributo service_resource_type en el recurso alicloud_privatelink_vpc_endpoint_service para configurar correctamente los recursos del servicio.",
		"fr": "Définissez l'attribut service_resource_type sur la ressource alicloud_privatelink_vpc_endpoint_service pour configurer correctement les ressources du service.",
		"pt": "Defina o atributo service_resource_type no recurso alicloud_privatelink_vpc_endpoint_service para configurar corretamente os recursos do serviço."
	},
	"resource_types": ["alicloud_privatelink_vpc_endpoint_service"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_privatelink_vpc_endpoint_service")
	srt := tf.get_attribute(resource, "service_resource_type", "")
	srt == ""
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_privatelink_vpc_endpoint_service.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
