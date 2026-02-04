package infraguard.rules.aliyun.slb_all_listenter_has_server

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-all-listenter-has-server",
	"name": {
		"en": "SLB All Listeners Have Backend Servers",
		"zh": "SLB 负载均衡的所有监听都至少添加了指定数量的后端服务器",
		"ja": "SLB のすべてのリスナーにバックエンドサーバーがある",
		"de": "SLB alle Listener haben Backend-Server",
		"es": "Todos los Oyentes SLB Tienen Servidores Backend",
		"fr": "Tous les Auditeurs SLB ont des Serveurs Backend",
		"pt": "Todos os Ouvintes SLB Têm Servidores Backend"
	},
	"severity": "medium",
	"description": {
		"en": "All listeners of SLB instances should have at least the specified number of backend servers attached.",
		"zh": "SLB 负载均衡的所有监听都至少添加参数指定数量的后端服务器，视为合规。默认至少添加一台服务器视为合规。",
		"ja": "SLB インスタンスのすべてのリスナーには、少なくとも指定された数のバックエンドサーバーが接続されている必要があります。",
		"de": "Alle Listener von SLB-Instanzen sollten mindestens die angegebene Anzahl von Backend-Servern angehängt haben.",
		"es": "Todos los oyentes de las instancias SLB deben tener al menos el número especificado de servidores backend adjuntos.",
		"fr": "Tous les auditeurs des instances SLB doivent avoir au moins le nombre spécifié de serveurs backend attachés.",
		"pt": "Todos os ouvintes das instâncias SLB devem ter pelo menos o número especificado de servidores backend anexados."
	},
	"reason": {
		"en": "Listeners without backend servers cannot forward traffic, leading to service unavailability.",
		"zh": "没有后端服务器的监听无法转发流量，导致服务不可用。",
		"ja": "バックエンドサーバーがないリスナーはトラフィックを転送できず、サービスが利用できなくなります。",
		"de": "Listener ohne Backend-Server können keinen Datenverkehr weiterleiten, was zu Service-Unverfügbarkeit führt.",
		"es": "Los oyentes sin servidores backend no pueden reenviar tráfico, lo que lleva a la indisponibilidad del servicio.",
		"fr": "Les auditeurs sans serveurs backend ne peuvent pas transférer le trafic, ce qui entraîne l'indisponibilité du service.",
		"pt": "Ouvintes sem servidores backend não podem encaminhar tráfego, levando à indisponibilidade do serviço."
	},
	"recommendation": {
		"en": "Attach at least the minimum required number of backend servers to all listeners.",
		"zh": "为所有监听至少添加所需最小数量的后端服务器。",
		"ja": "すべてのリスナーに少なくとも最小限必要な数のバックエンドサーバーを接続します。",
		"de": "Fügen Sie allen Listenern mindestens die mindestens erforderliche Anzahl von Backend-Servern hinzu.",
		"es": "Adjunte al menos el número mínimo requerido de servidores backend a todos los oyentes.",
		"fr": "Attachez au moins le nombre minimum requis de serveurs backend à tous les auditeurs.",
		"pt": "Anexe pelo menos o número mínimo necessário de servidores backend a todos os ouvintes."
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Listeners"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
