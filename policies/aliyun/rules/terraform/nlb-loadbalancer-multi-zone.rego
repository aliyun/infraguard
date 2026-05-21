package infraguard.rules.terraform.nlb_loadbalancer_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "nlb-loadbalancer-multi-zone",
	"severity": "medium",
	"name": {
		"en": "NLB LoadBalancer Multi-Zone Deployment",
		"zh": "使用多可用区的网络负载均衡实例",
		"ja": "NLB ロードバランサーマルチゾーン展開",
		"de": "NLB LoadBalancer Multi-Zonen-Bereitstellung",
		"es": "Implementación Multi-Zona del Equilibrador de Carga NLB",
		"fr": "Déploiement Multi-Zone de l'Équilibreur de Charge NLB",
		"pt": "Implantação Multi-Zona do Balanceador de Carga NLB"
	},
	"description": {
		"en": "NLB LoadBalancer instances should be deployed across at least two availability zones for high availability.",
		"zh": "使用多可用区的网络负载均衡实例，视为合规。",
		"ja": "NLB LoadBalancer インスタンスは、高可用性のために少なくとも 2 つの可用性ゾーンに展開する必要があります。",
		"de": "NLB LoadBalancer-Instanzen sollten über mindestens zwei Verfügbarkeitszonen für Hochverfügbarkeit bereitgestellt werden.",
		"es": "Las instancias del equilibrador de carga NLB deben implementarse en al menos dos zonas de disponibilidad para alta disponibilidad.",
		"fr": "Les instances d'équilibreur de charge NLB doivent être déployées sur au moins deux zones de disponibilité pour une haute disponibilité.",
		"pt": "As instâncias do balanceador de carga NLB devem ser implantadas em pelo menos duas zonas de disponibilidade para alta disponibilidade."
	},
	"reason": {
		"en": "The NLB LoadBalancer is deployed in fewer than two availability zones.",
		"zh": "网络负载均衡实例部署在少于两个可用区，存在单点故障风险。",
		"ja": "NLB LoadBalancer が 2 未満の可用性ゾーンに展開されているため、単一障害点のリスクが作成されます。",
		"de": "Der NLB LoadBalancer wird in weniger als zwei Verfügbarkeitszonen bereitgestellt, was ein Single Point of Failure-Risiko schafft.",
		"es": "El equilibrador de carga NLB se implementa en menos de dos zonas de disponibilidad, creando un riesgo de punto único de falla.",
		"fr": "L'équilibreur de charge NLB est déployé dans moins de deux zones de disponibilité, créant un risque de point de défaillance unique.",
		"pt": "O balanceador de carga NLB é implantado em menos de duas zonas de disponibilidade, criando um risco de ponto único de falha."
	},
	"recommendation": {
		"en": "Configure at least two zone mappings for the NLB instance.",
		"zh": "在 ZoneMappings 中配置至少两个可用区映射，以确保高可用性。",
		"ja": "高可用性を確保するために、ZoneMappings プロパティに少なくとも 2 つのゾーンマッピングを設定します。",
		"de": "Konfigurieren Sie mindestens zwei Zonen-Mappings in der Eigenschaft ZoneMappings, um Hochverfügbarkeit sicherzustellen.",
		"es": "Configure al menos dos mapeos de zona en la propiedad ZoneMappings para garantizar alta disponibilidad.",
		"fr": "Configurez au moins deux mappages de zone dans la propriété ZoneMappings pour assurer une haute disponibilité.",
		"pt": "Configure pelo menos dois mapeamentos de zona na propriedade ZoneMappings para garantir alta disponibilidade."
	},
	"resource_types": ["alicloud_nlb_load_balancer"],
	"iac_type": "terraform"
}

as_array(value) := value if is_array(value)

else := [value] if is_object(value)

else := []

unique_zones(resource) := zones if {
	mappings := as_array(tf.get_attribute(resource, "zone_mappings", []))
	zones := {zone |
		some mapping in mappings
		zone := object.get(mapping, "zone_id", "")
		zone != ""
		not tf.is_unknown(zone)
	}
}

is_multi_zone(resource) if {
	count(unique_zones(resource)) >= 2
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_nlb_load_balancer")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_nlb_load_balancer.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
