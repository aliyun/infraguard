package infraguard.rules.terraform.transit_router_vpc_attachment_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "transit-router-vpc-attachment-multi-zone",
	"severity": "high",
	"name": {
		"en": "Transit Router VPC Attachment Multi-Zone Configuration",
		"zh": "为转发路由器 VPC 连接设置多个可用区",
		"ja": "トランジットルーター VPC アタッチメントマルチゾーン設定",
		"de": "Transit Router VPC-Anhang Multi-Zonen-Konfiguration",
		"es": "Configuración Multi-Zona de Conexión VPC del Enrutador de Tránsito",
		"fr": "Configuration Multi-Zone de Connexion VPC du Routeur de Transit",
		"pt": "Configuração Multi-Zona de Anexo VPC do Roteador de Trânsito"
	},
	"description": {
		"en": "Transit Router VPC attachments should be configured with vSwitches in at least two different availability zones for cross-zone high availability.",
		"zh": "为转发路由器的 VPC 连接设置两个分布在不同可用区的交换机，保障产品跨可用区的高可用性，视为合规。",
		"ja": "トランジットルーター VPC アタッチメントは、クロスゾーン高可用性のために、少なくとも 2 つの異なる可用性ゾーンに vSwitch を設定する必要があります。",
		"de": "Transit Router VPC-Anhänge sollten mit vSwitches in mindestens zwei verschiedenen Verfügbarkeitszonen für regionsübergreifende Hochverfügbarkeit konfiguriert werden.",
		"es": "Las conexiones VPC del enrutador de tránsito deben configurarse con vSwitches en al menos dos zonas de disponibilidad diferentes para alta disponibilidad entre zonas.",
		"fr": "Les connexions VPC du routeur de transit doivent être configurées avec des vSwitches dans au moins deux zones de disponibilité différentes pour une haute disponibilité inter-zones.",
		"pt": "Os anexos VPC do roteador de trânsito devem ser configurados com vSwitches em pelo menos duas zonas de disponibilidade diferentes para alta disponibilidade entre zonas."
	},
	"reason": {
		"en": "The Transit Router VPC attachment is configured with vSwitches in only one availability zone, creating a single point of failure.",
		"zh": "转发路由器 VPC 连接仅配置了一个可用区的交换机，存在单点故障风险。",
		"ja": "トランジットルーター VPC アタッチメントが 1 つの可用性ゾーンにのみ vSwitch で設定されているため、単一障害点が作成されます。",
		"de": "Der Transit Router VPC-Anhang ist nur mit vSwitches in einer Verfügbarkeitszone konfiguriert, was einen Single Point of Failure schafft.",
		"es": "La conexión VPC del enrutador de tránsito está configurada con vSwitches en solo una zona de disponibilidad, creando un punto único de falla.",
		"fr": "La connexion VPC du routeur de transit est configurée avec des vSwitches dans une seule zone de disponibilité, créant un point de défaillance unique.",
		"pt": "O anexo VPC do roteador de trânsito está configurado com vSwitches em apenas uma zona de disponibilidade, criando um ponto único de falha."
	},
	"recommendation": {
		"en": "Configure at least two zone_mappings blocks with different zone_id values for cross-zone high availability.",
		"zh": "配置至少两个具有不同 zone_id 值的 zone_mappings 块以实现跨可用区高可用性。",
		"ja": "クロスゾーン高可用性のために、異なる zone_id 値を持つ少なくとも 2 つの zone_mappings ブロックを設定します。",
		"de": "Konfigurieren Sie mindestens zwei zone_mappings-Blöcke mit verschiedenen zone_id-Werten für regionsübergreifende Hochverfügbarkeit.",
		"es": "Configure al menos dos bloques zone_mappings con diferentes valores de zone_id para alta disponibilidad entre zonas.",
		"fr": "Configurez au moins deux blocs zone_mappings avec différentes valeurs zone_id pour une haute disponibilité inter-zones.",
		"pt": "Configure pelo menos dois blocos zone_mappings com diferentes valores zone_id para alta disponibilidade entre zonas."
	},
	"resource_types": ["alicloud_cen_transit_router_vpc_attachment"],
	"iac_type": "terraform"
}

# Check if VPC attachment has vSwitches in multiple zones
has_multiple_zones(resource) if {
	mappings := tf.get_attribute(resource, "zone_mappings", [])
	is_array(mappings)
	zones := {zone_id | some mapping in mappings; zone_id := mapping.zone_id}
	count(zones) >= 2
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_cen_transit_router_vpc_attachment")
	not has_multiple_zones(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_cen_transit_router_vpc_attachment.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
