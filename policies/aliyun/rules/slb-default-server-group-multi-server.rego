package infraguard.rules.aliyun.slb_default_server_group_multi_server

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-default-server-group-multi-server",
	"name": {
		"en": "SLB Default Server Group Has Multiple Servers",
		"zh": "SLB 实例默认服务器组包含至少两台服务器",
		"ja": "SLB デフォルトサーバーグループに複数のサーバーがある",
		"de": "SLB-Standard-Servergruppe hat mehrere Server",
		"es": "El Grupo de Servidores Predeterminado SLB Tiene Múltiples Servidores",
		"fr": "Le Groupe de Serveurs par Défaut SLB a Plusieurs Serveurs",
		"pt": "O Grupo de Servidores Padrão do SLB Tem Múltiplos Servidores",
	},
	"severity": "medium",
	"description": {
		"en": "The default server group of SLB instances should have at least two servers to avoid single point of failure.",
		"zh": "SLB 实例的默认服务器组至少添加两台服务器，视为合规。",
		"ja": "SLB インスタンスのデフォルトサーバーグループは、単一障害点を避けるために少なくとも 2 つのサーバーを持つ必要があります。",
		"de": "Die Standard-Servergruppe von SLB-Instanzen sollte mindestens zwei Server haben, um einen Single Point of Failure zu vermeiden.",
		"es": "El grupo de servidores predeterminado de las instancias SLB debe tener al menos dos servidores para evitar un punto único de falla.",
		"fr": "Le groupe de serveurs par défaut des instances SLB doit avoir au moins deux serveurs pour éviter un point de défaillance unique.",
		"pt": "O grupo de servidores padrão das instâncias SLB deve ter pelo menos dois servidores para evitar um ponto único de falha.",
	},
	"reason": {
		"en": "A single backend server creates a single point of failure and reduces availability.",
		"zh": "单一后端服务器创建单点故障并降低可用性。",
		"ja": "単一のバックエンドサーバーは単一障害点を作成し、可用性を低下させます。",
		"de": "Ein einzelner Backend-Server schafft einen Single Point of Failure und reduziert die Verfügbarkeit.",
		"es": "Un solo servidor backend crea un punto único de falla y reduce la disponibilidad.",
		"fr": "Un seul serveur backend crée un point de défaillance unique et réduit la disponibilité.",
		"pt": "Um único servidor backend cria um ponto único de falha e reduz a disponibilidade.",
	},
	"recommendation": {
		"en": "Add at least two servers to the default server group for high availability.",
		"zh": "为实现高可用性，在默认服务器组中至少添加两台服务器。",
		"ja": "高可用性のために、デフォルトサーバーグループに少なくとも 2 つのサーバーを追加します。",
		"de": "Fügen Sie mindestens zwei Server zur Standard-Servergruppe hinzu, um Hochverfügbarkeit zu gewährleisten.",
		"es": "Agregue al menos dos servidores al grupo de servidores predeterminado para alta disponibilidad.",
		"fr": "Ajoutez au moins deux serveurs au groupe de serveurs par défaut pour une haute disponibilité.",
		"pt": "Adicione pelo menos dois servidores ao grupo de servidores padrão para alta disponibilidade.",
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

has_multiple_servers(resource) if {
	backend_servers := helpers.get_property(resource, "BackendServers", [])
	count(backend_servers) >= 2
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not has_multiple_servers(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "BackendServers"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
