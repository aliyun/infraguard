package infraguard.rules.aliyun.gwlb_loadbalancer_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "gwlb-loadbalancer-multi-zone",
	"name": {
		"en": "GWLB LoadBalancer Multi-Zone Deployment",
		"zh": "使用多可用区的网关型负载均衡实例",
		"ja": "GWLB ロードバランサーのマルチゾーン展開",
		"de": "GWLB-LoadBalancer Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona del Balanceador de Carga GWLB",
		"fr": "Déploiement Multi-Zone du Répartiteur de Charge GWLB",
		"pt": "Implantação Multi-Zona do Balanceador de Carga GWLB"
	},
	"severity": "medium",
	"description": {
		"en": "GWLB LoadBalancer instances should be deployed across at least two availability zones for high availability.",
		"zh": "使用多可用区的网关型负载均衡实例，视为合规。",
		"ja": "GWLB ロードバランサーインスタンスは高可用性のために少なくとも 2 つの可用性ゾーンにまたがって展開する必要があります。",
		"de": "GWLB-LoadBalancer-Instanzen sollten für hohe Verfügbarkeit über mindestens zwei Verfügbarkeitszonen hinweg bereitgestellt werden.",
		"es": "Las instancias del Balanceador de Carga GWLB deben desplegarse en al menos dos zonas de disponibilidad para alta disponibilidad.",
		"fr": "Les instances du Répartiteur de Charge GWLB doivent être déployées sur au moins deux zones de disponibilité pour une haute disponibilité.",
		"pt": "As instâncias do Balanceador de Carga GWLB devem ser implantadas em pelo menos duas zonas de disponibilidade para alta disponibilidade."
	},
	"reason": {
		"en": "The GWLB LoadBalancer is deployed in fewer than two availability zones, creating a single point of failure risk.",
		"zh": "网关型负载均衡实例部署在少于两个可用区，存在单点故障风险。",
		"ja": "GWLB ロードバランサーが 2 つ未満の可用性ゾーンに展開されており、単一障害点のリスクが生じています。",
		"de": "Der GWLB-LoadBalancer wird in weniger als zwei Verfügbarkeitszonen bereitgestellt, was ein Single-Point-of-Failure-Risiko schafft.",
		"es": "El Balanceador de Carga GWLB se despliega en menos de dos zonas de disponibilidad, creando un riesgo de punto único de falla.",
		"fr": "Le Répartiteur de Charge GWLB est déployé dans moins de deux zones de disponibilité, créant un risque de point de défaillance unique.",
		"pt": "O Balanceador de Carga GWLB está implantado em menos de duas zonas de disponibilidade, criando um risco de ponto único de falha."
	},
	"recommendation": {
		"en": "Configure at least two zone mappings in the ZoneMappings property to ensure high availability.",
		"zh": "在 ZoneMappings 属性中配置至少两个可用区映射，以确保高可用性。",
		"ja": "高可用性を確保するために、ZoneMappings プロパティで少なくとも 2 つのゾーンマッピングを設定します。",
		"de": "Konfigurieren Sie mindestens zwei Zonen-Mappings in der ZoneMappings-Eigenschaft, um hohe Verfügbarkeit zu gewährleisten.",
		"es": "Configure al menos dos mapeos de zona en la propiedad ZoneMappings para garantizar alta disponibilidad.",
		"fr": "Configurez au moins deux mappages de zone dans la propriété ZoneMappings pour assurer une haute disponibilité.",
		"pt": "Configure pelo menos dois mapeamentos de zona na propriedade ZoneMappings para garantir alta disponibilidade."
	},
	"resource_types": ["ALIYUN::GWLB::LoadBalancer"],
}

# Check if LoadBalancer has multiple zones
has_multiple_zones(resource) if {
	zone_mappings := resource.Properties.ZoneMappings
	count(zone_mappings) >= 2
}

# Deny rule: GWLB LoadBalancers must be deployed in multiple zones
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::GWLB::LoadBalancer")
	not has_multiple_zones(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ZoneMappings"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
