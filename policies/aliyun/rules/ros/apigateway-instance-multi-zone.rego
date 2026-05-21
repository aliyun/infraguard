package infraguard.rules.aliyun.apigateway_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "apigateway-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "API Gateway Instance Multi-Zone Deployment",
		"zh": "使用多可用区的 API 网关实例",
		"ja": "API ゲートウェイインスタンスマルチゾーン展開",
		"de": "API Gateway-Instanz Multi-Zonen-Bereitstellung",
		"es": "Implementación Multi-Zona de Instancia de API Gateway",
		"fr": "Déploiement Multi-Zone d'Instance API Gateway",
		"pt": "Implantação Multi-Zona de Instância API Gateway"
	},
	"description": {
		"en": "API Gateway instances should be deployed in multi-zone configuration for high availability.",
		"zh": "使用多可用区的 API 网关实例，视为合规。",
		"ja": "API ゲートウェイインスタンスは、高可用性のためにマルチゾーン設定に展開する必要があります。",
		"de": "API Gateway-Instanzen sollten in Multi-Zonen-Konfiguration für Hochverfügbarkeit bereitgestellt werden.",
		"es": "Las instancias de API Gateway deben implementarse en configuración multi-zona para alta disponibilidad.",
		"fr": "Les instances API Gateway doivent être déployées en configuration multi-zone pour une haute disponibilité.",
		"pt": "As instâncias do API Gateway devem ser implantadas em configuração multi-zona para alta disponibilidade."
	},
	"reason": {
		"en": "The API Gateway instance is deployed in a single availability zone, creating a single point of failure.",
		"zh": "API 网关实例部署在单个可用区，存在单点故障风险。",
		"ja": "API ゲートウェイインスタンスが単一の可用性ゾーンに展開されているため、単一障害点が作成されます。",
		"de": "Die API Gateway-Instanz wird in einer einzelnen Verfügbarkeitszone bereitgestellt, was einen Single Point of Failure schafft.",
		"es": "La instancia de API Gateway se implementa en una sola zona de disponibilidad, creando un punto único de falla.",
		"fr": "L'instance API Gateway est déployée dans une seule zone de disponibilité, créant un point de défaillance unique.",
		"pt": "A instância do API Gateway é implantada em uma única zona de disponibilidade, criando um ponto único de falha."
	},
	"recommendation": {
		"en": "Deploy the API Gateway instance in a multi-zone configuration by specifying a ZoneId with MAZ (Multi-AZ) format, such as 'cn-beijing-MAZ2(f,g)'.",
		"zh": "通过指定 MAZ（多可用区）格式的 ZoneId（如'cn-beijing-MAZ2(f,g)'），将 API 网关实例部署在多可用区配置中。",
		"ja": "MAZ（マルチ AZ）形式の ZoneId（例：'cn-beijing-MAZ2(f,g)'）を指定して、API ゲートウェイインスタンスをマルチゾーン設定に展開します。",
		"de": "Stellen Sie die API Gateway-Instanz in einer Multi-Zonen-Konfiguration bereit, indem Sie eine ZoneId im MAZ (Multi-AZ) Format angeben, z. B. 'cn-beijing-MAZ2(f,g)'.",
		"es": "Implemente la instancia de API Gateway en una configuración multi-zona especificando un ZoneId con formato MAZ (Multi-AZ), como 'cn-beijing-MAZ2(f,g)'.",
		"fr": "Déployez l'instance API Gateway dans une configuration multi-zone en spécifiant un ZoneId au format MAZ (Multi-AZ), tel que 'cn-beijing-MAZ2(f,g)'.",
		"pt": "Implante a instância do API Gateway em uma configuração multi-zona especificando um ZoneId com formato MAZ (Multi-AZ), como 'cn-beijing-MAZ2(f,g)'."
	},
	"resource_types": ["ALIYUN::ApiGateway::Instance"]
}

# Check if zone ID indicates multi-zone deployment
# Multi-zone format: cn-region-MAZ#(zone1,zone2,...)
is_multi_zone(zone_id) if {
	contains(zone_id, "MAZ")
	contains(zone_id, "(")
	contains(zone_id, ")")
}

# Check if instance is multi-zone
has_multi_zone_deployment(resource) if {
	zone_id := resource.Properties.ZoneId
	is_multi_zone(zone_id)
}

# Deny rule: API Gateway instances must be multi-zone
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Instance")
	not has_multi_zone_deployment(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ZoneId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
