package infraguard.rules.aliyun.slb_all_listener_servers_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "slb-all-listener-servers-multi-zone",
	"name": {
		"en": "SLB Multi-Zone with Multi-Zone Backend Servers",
		"zh": "使用多可用区 SLB 实例并为服务器组配置多个可用区资源",
		"ja": "マルチゾーン SLB インスタンスとマルチゾーンバックエンドサーバー",
		"de": "SLB Multi-Zone mit Multi-Zone-Backend-Servern",
		"es": "SLB Multi-zona con Servidores Backend Multi-zona",
		"fr": "SLB Multi-zones avec Serveurs Backend Multi-zones",
		"pt": "SLB Multi-zona com Servidores Backend Multi-zona",
	},
	"severity": "high",
	"description": {
		"en": "SLB instances should be multi-zone, and all server groups used by listeners should have resources added from multiple zones.",
		"zh": "SLB 实例为多可用区，并且 SLB 实例下所有监听使用的服务器组中添加了多个可用区的资源，视为合规。",
		"ja": "SLB インスタンスはマルチゾーンである必要があり、リスナーが使用するすべてのサーバーグループに複数のゾーンからのリソースが追加されている必要があります。",
		"de": "SLB-Instanzen sollten Multi-Zone sein, und alle von Listenern verwendeten Servergruppen sollten Ressourcen aus mehreren Zonen hinzugefügt haben.",
		"es": "Las instancias SLB deben ser multi-zona, y todos los grupos de servidores utilizados por los listeners deben tener recursos agregados desde múltiples zonas.",
		"fr": "Les instances SLB doivent être multi-zones, et tous les groupes de serveurs utilisés par les listeners doivent avoir des ressources ajoutées depuis plusieurs zones.",
		"pt": "Instâncias SLB devem ser multi-zona, e todos os grupos de servidores usados pelos listeners devem ter recursos adicionados de múltiplas zonas.",
	},
	"reason": {
		"en": "Single zone deployment or single zone backend servers lack high availability and may lead to service interruption during zone failure.",
		"zh": "单可用区部署或后端服务器仅位于单个可用区缺乏高可用性，可能在可用区故障时导致服务中断。",
		"ja": "単一ゾーン展開または単一ゾーンのバックエンドサーバーは高可用性に欠け、ゾーン障害時にサービス中断が発生する可能性があります。",
		"de": "Einzelzonen-Bereitstellung oder Einzelzonen-Backend-Server mangelt es an hoher Verfügbarkeit und kann zu Dienstunterbrechungen während eines Zonenausfalls führen.",
		"es": "La implementación de zona única o servidores backend de zona única carecen de alta disponibilidad y pueden provocar interrupciones del servicio durante una falla de zona.",
		"fr": "Le déploiement en zone unique ou les serveurs backend en zone unique manquent de haute disponibilité et peuvent entraîner une interruption de service lors d'une panne de zone.",
		"pt": "A implantação de zona única ou servidores backend de zona única carecem de alta disponibilidade e podem levar à interrupção do serviço durante falha de zona.",
	},
	"recommendation": {
		"en": "Configure SLB instances with master and slave zones, and ensure backend server groups include instances from different availability zones.",
		"zh": "为 SLB 实例配置主备可用区，并确保后端服务器组包含来自不同可用区的实例。",
		"ja": "マスターゾーンとスレーブゾーンで SLB インスタンスを設定し、バックエンドサーバーグループに異なる可用性ゾーンからのインスタンスが含まれるようにします。",
		"de": "Konfigurieren Sie SLB-Instanzen mit Master- und Slave-Zonen und stellen Sie sicher, dass Backend-Servergruppen Instanzen aus verschiedenen Verfügbarkeitszonen enthalten.",
		"es": "Configure instancias SLB con zonas maestra y esclava, y asegúrese de que los grupos de servidores backend incluyan instancias de diferentes zonas de disponibilidad.",
		"fr": "Configurez les instances SLB avec des zones maître et esclave, et assurez-vous que les groupes de serveurs backend incluent des instances de différentes zones de disponibilité.",
		"pt": "Configure instâncias SLB com zonas mestre e escrava, e garanta que grupos de servidores backend incluam instâncias de diferentes zonas de disponibilidade.",
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

# Check if SLB instance has slave zone configured
is_multi_zone(resource) if {
	helpers.has_property(resource, "SlaveZoneId")
	slave_zone := resource.Properties.SlaveZoneId
	slave_zone != ""
}

# Deny rule: SLB instances should be multi-zone
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SlaveZoneId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
