package infraguard.rules.aliyun.slb_instance_default_server_group_multi_zone

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-instance-default-server-group-multi-zone",
	"name": {
		"en": "SLB Default Server Group Multi-Zone",
		"zh": "SLB 负载均衡默认服务器组添加多个可用区资源",
		"ja": "SLB デフォルトサーバーグループのマルチゾーン",
		"de": "SLB Standard-Server-Gruppe Multi-Zone",
		"es": "Grupo de Servidores Predeterminado SLB Multi-Zona",
		"fr": "Groupe de Serveurs par Défaut SLB Multi-Zone",
		"pt": "Grupo de Servidores Padrão SLB Multi-Zona"
	},
	"severity": "medium",
	"description": {
		"en": "The default server group of SLB instances should have resources distributed across multiple availability zones.",
		"zh": "SLB 负载均衡的默认服务器组挂载资源分布在多个可用区，视为合规。默认服务器组无挂载任何资源时不适用本规则，视为不适用。",
		"ja": "SLB インスタンスのデフォルトサーバーグループは、リソースを複数の可用性ゾーンに分散させる必要があります。",
		"de": "Die Standard-Server-Gruppe von SLB-Instanzen sollte Ressourcen über mehrere Verfügbarkeitszonen verteilt haben.",
		"es": "El grupo de servidores predeterminado de las instancias SLB debe tener recursos distribuidos en múltiples zonas de disponibilidad.",
		"fr": "Le groupe de serveurs par défaut des instances SLB doit avoir des ressources distribuées sur plusieurs zones de disponibilité.",
		"pt": "O grupo de servidores padrão das instâncias SLB deve ter recursos distribuídos em múltiplas zonas de disponibilidade."
	},
	"reason": {
		"en": "Single-zone backend servers create a single point of failure and reduce availability.",
		"zh": "单可用区后端服务器创建单点故障并降低可用性。",
		"ja": "単一ゾーンのバックエンドサーバーは単一障害点を作成し、可用性を低下させます。",
		"de": "Einzelzonen-Backend-Server erstellen einen Single Point of Failure und reduzieren die Verfügbarkeit.",
		"es": "Los servidores backend de zona única crean un punto único de falla y reducen la disponibilidad.",
		"fr": "Les serveurs backend à zone unique créent un point de défaillance unique et réduisent la disponibilité.",
		"pt": "Servidores backend de zona única criam um ponto único de falha e reduzem a disponibilidade."
	},
	"recommendation": {
		"en": "Distribute backend servers across multiple availability zones for high availability.",
		"zh": "为实现高可用性，将后端服务器分布在多个可用区。",
		"ja": "高可用性のために、バックエンドサーバーを複数の可用性ゾーンに分散します。",
		"de": "Verteilen Sie Backend-Server über mehrere Verfügbarkeitszonen für hohe Verfügbarkeit.",
		"es": "Distribuya los servidores backend en múltiples zonas de disponibilidad para alta disponibilidad.",
		"fr": "Répartissez les serveurs backend sur plusieurs zones de disponibilité pour une haute disponibilité.",
		"pt": "Distribua servidores backend em múltiplas zonas de disponibilidade para alta disponibilidade."
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

has_multi_zone_servers(resource) if {
	backend_servers := helpers.get_property(resource, "BackendServers", [])

	# Check if servers are in different zones
	count(backend_servers) > 1
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	backend_servers := helpers.get_property(resource, "BackendServers", [])
	count(backend_servers) > 0
	not has_multi_zone_servers(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "BackendServers"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
