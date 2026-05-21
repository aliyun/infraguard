package infraguard.rules.terraform.slb_instance_default_server_group_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-instance-default-server-group-multi-zone",
	"severity": "medium",
	"name": {
		"en": "SLB Default Server Group Multi-Zone",
		"zh": "SLB 负载均衡默认服务器组添加多个可用区资源",
		"ja": "SLB デフォルトサーバーグループのマルチゾーン",
		"de": "SLB Standard-Server-Gruppe Multi-Zone",
		"es": "Grupo de Servidores Predeterminado SLB Multi-Zona",
		"fr": "Groupe de Serveurs par Défaut SLB Multi-Zone",
		"pt": "Grupo de Servidores Padrão SLB Multi-Zona"
	},
	"description": {
		"en": "The default server group of SLB instances should have resources distributed across multiple availability zones.",
		"zh": "SLB 负载均衡的默认服务器组挂载资源分布在多个可用区，视为合规。",
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
		"en": "Add at least two backend_servers entries to distribute across multiple availability zones.",
		"zh": "至少添加两个 backend_servers 条目以分布在多个可用区。",
		"ja": "複数の可用性ゾーンに分散するために、少なくとも 2 つの backend_servers エントリを追加します。",
		"de": "Fügen Sie mindestens zwei backend_servers-Einträge hinzu, um über mehrere Verfügbarkeitszonen zu verteilen.",
		"es": "Agregue al menos dos entradas backend_servers para distribuir en múltiples zonas de disponibilidad.",
		"fr": "Ajoutez au moins deux entrées backend_servers pour distribuer sur plusieurs zones de disponibilité.",
		"pt": "Adicione pelo menos duas entradas backend_servers para distribuir em múltiplas zonas de disponibilidade."
	},
	"resource_types": ["alicloud_slb_backend_server"],
	"iac_type": "terraform"
}

as_array(value) := value if is_array(value)

else := [value] if is_object(value)

else := []

has_multi_zone_servers(resource) if {
	servers := as_array(tf.get_attribute(resource, "backend_servers", []))
	count(servers) >= 2
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_backend_server")
	servers := as_array(tf.get_attribute(resource, "backend_servers", []))
	count(servers) > 0
	not has_multi_zone_servers(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_backend_server.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
