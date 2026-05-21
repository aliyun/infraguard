package infraguard.rules.terraform.slb_all_listener_servers_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-all-listener-servers-multi-zone",
	"severity": "medium",
	"name": {
		"en": "SLB Multi-Zone with Multi-Zone Backend Servers",
		"zh": "使用多可用区 SLB 实例并为服务器组配置多个可用区资源",
		"ja": "マルチゾーン SLB インスタンスとマルチゾーンバックエンドサーバー",
		"de": "SLB Multi-Zone mit Multi-Zone-Backend-Servern",
		"es": "SLB Multi-zona con Servidores Backend Multi-zona",
		"fr": "SLB Multi-zones avec Serveurs Backend Multi-zones",
		"pt": "SLB Multi-zona com Servidores Backend Multi-zona"
	},
	"description": {
		"en": "SLB instances should be multi-zone, with master_zone_id and slave_zone_id configured to different zones.",
		"zh": "SLB 实例为多可用区，master_zone_id 和 slave_zone_id 配置为不同可用区，视为合规。",
		"ja": "SLB インスタンスはマルチゾーンである必要があり、master_zone_id と slave_zone_id が異なるゾーンに設定されている必要があります。",
		"de": "SLB-Instanzen sollten Multi-Zone sein, mit master_zone_id und slave_zone_id in verschiedenen Zonen konfiguriert.",
		"es": "Las instancias SLB deben ser multi-zona, con master_zone_id y slave_zone_id configurados en diferentes zonas.",
		"fr": "Les instances SLB doivent être multi-zones, avec master_zone_id et slave_zone_id configurés dans des zones différentes.",
		"pt": "Instâncias SLB devem ser multi-zona, com master_zone_id e slave_zone_id configurados em zonas diferentes."
	},
	"reason": {
		"en": "Single zone deployment or single zone backend servers lack high availability and may lead to service interruption during zone failure.",
		"zh": "单可用区部署或后端服务器仅位于单个可用区缺乏高可用性，可能在可用区故障时导致服务中断。",
		"ja": "単一ゾーン展開または単一ゾーンのバックエンドサーバーは高可用性に欠け、ゾーン障害時にサービス中断が発生する可能性があります。",
		"de": "Einzelzonen-Bereitstellung oder Einzelzonen-Backend-Server mangelt es an hoher Verfügbarkeit und kann zu Dienstunterbrechungen während eines Zonenausfalls führen.",
		"es": "La implementación de zona única o servidores backend de zona única carecen de alta disponibilidad y pueden provocar interrupciones del servicio durante una falla de zona.",
		"fr": "Le déploiement en zone unique ou les serveurs backend en zone unique manquent de haute disponibilité et peuvent entraîner une interruption de service lors d'une panne de zone.",
		"pt": "A implantação de zona única ou servidores backend de zona única carecem de alta disponibilidade e podem levar à interrupção do serviço durante falha de zona."
	},
	"recommendation": {
		"en": "Configure SLB instances with different master_zone_id and slave_zone_id for high availability.",
		"zh": "为 SLB 实例配置不同的 master_zone_id 和 slave_zone_id 以实现高可用性。",
		"ja": "高可用性のために、SLB インスタンスに異なる master_zone_id と slave_zone_id を設定します。",
		"de": "Konfigurieren Sie SLB-Instanzen mit verschiedenen master_zone_id und slave_zone_id für Hochverfügbarkeit.",
		"es": "Configure instancias SLB con diferentes master_zone_id y slave_zone_id para alta disponibilidad.",
		"fr": "Configurez les instances SLB avec des master_zone_id et slave_zone_id différents pour une haute disponibilité.",
		"pt": "Configure instâncias SLB com master_zone_id e slave_zone_id diferentes para alta disponibilidade."
	},
	"resource_types": ["alicloud_slb_load_balancer"],
	"iac_type": "terraform"
}

is_multi_zone(resource) if {
	master := tf.get_attribute(resource, "master_zone_id", "")
	slave := tf.get_attribute(resource, "slave_zone_id", "")
	master != ""
	slave != ""
	master != slave
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_load_balancer")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_load_balancer.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
