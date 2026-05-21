package infraguard.rules.terraform.slb_all_listenter_has_server

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-all-listenter-has-server",
	"severity": "medium",
	"name": {
		"en": "SLB All Listeners Have Backend Servers",
		"zh": "SLB 负载均衡的所有监听都至少添加了指定数量的后端服务器",
		"ja": "SLB のすべてのリスナーにバックエンドサーバーがある",
		"de": "SLB alle Listener haben Backend-Server",
		"es": "Todos los Oyentes SLB Tienen Servidores Backend",
		"fr": "Tous les Auditeurs SLB ont des Serveurs Backend",
		"pt": "Todos os Ouvintes SLB Têm Servidores Backend"
	},
	"description": {
		"en": "When SLB load balancers exist, there should be at least one backend server resource configured.",
		"zh": "当 SLB 负载均衡存在时，应至少配置一个后端服务器资源，视为合规。",
		"ja": "SLB ロードバランサーが存在する場合、少なくとも 1 つのバックエンドサーバーリソースが設定されている必要があります。",
		"de": "Wenn SLB-Lastausgleicher vorhanden sind, sollte mindestens eine Backend-Server-Ressource konfiguriert sein.",
		"es": "Cuando existen balanceadores de carga SLB, debe haber al menos un recurso de servidor backend configurado.",
		"fr": "Lorsque des équilibreurs de charge SLB existent, au moins une ressource de serveur backend doit être configurée.",
		"pt": "Quando balanceadores de carga SLB existem, deve haver pelo menos um recurso de servidor backend configurado."
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
		"en": "Add alicloud_slb_backend_server or alicloud_slb_server_group resources to attach backend servers to the SLB.",
		"zh": "添加 alicloud_slb_backend_server 或 alicloud_slb_server_group 资源以将后端服务器挂载到 SLB。",
		"ja": "alicloud_slb_backend_server または alicloud_slb_server_group リソースを追加して、バックエンドサーバーを SLB に接続します。",
		"de": "Fügen Sie alicloud_slb_backend_server- oder alicloud_slb_server_group-Ressourcen hinzu, um Backend-Server an den SLB anzuhängen.",
		"es": "Agregue recursos alicloud_slb_backend_server o alicloud_slb_server_group para adjuntar servidores backend al SLB.",
		"fr": "Ajoutez des ressources alicloud_slb_backend_server ou alicloud_slb_server_group pour attacher des serveurs backend au SLB.",
		"pt": "Adicione recursos alicloud_slb_backend_server ou alicloud_slb_server_group para anexar servidores backend ao SLB."
	},
	"resource_types": ["alicloud_slb_load_balancer"],
	"iac_type": "terraform"
}

has_backend_server if {
	tf.has_resource_type("alicloud_slb_backend_server")
}

has_backend_server if {
	tf.has_resource_type("alicloud_slb_server_group")
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_load_balancer")
	not has_backend_server
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
