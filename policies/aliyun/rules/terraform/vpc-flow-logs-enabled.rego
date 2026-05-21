package infraguard.rules.terraform.vpc_flow_logs_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "vpc-flow-logs-enabled",
	"severity": "medium",
	"name": {
		"en": "VPC Flow Logs Enabled",
		"zh": "VPC 开启流日志",
		"ja": "VPC フローログが有効",
		"de": "VPC-Flussprotokolle aktiviert",
		"es": "Registros de Flujo VPC Habilitados",
		"fr": "Journaux de Flux VPC Activés",
		"pt": "Logs de Fluxo VPC Habilitados"
	},
	"description": {
		"en": "Ensures VPC flow logs are enabled for monitoring network traffic.",
		"zh": "确保 VPC 开启了流日志，以便监控网络流量。",
		"ja": "ネットワークトラフィックを監視するために VPC フローログが有効になっていることを確認します。",
		"de": "Stellt sicher, dass VPC-Flussprotokolle für die Überwachung des Netzwerkverkehrs aktiviert sind.",
		"es": "Garantiza que los registros de flujo VPC estén habilitados para monitorear el tráfico de red.",
		"fr": "Garantit que les journaux de flux VPC sont activés pour surveiller le trafic réseau.",
		"pt": "Garante que os logs de fluxo VPC estejam habilitados para monitorar tráfego de rede."
	},
	"reason": {
		"en": "Flow logs provide visibility into network traffic patterns and help in security auditing.",
		"zh": "流日志提供了网络流量模式的可见性，有助于安全审计。",
		"ja": "フローログはネットワークトラフィックパターンの可視性を提供し、セキュリティ監査に役立ちます。",
		"de": "Flussprotokolle bieten Einblicke in Netzwerkverkehrsmuster und helfen bei Sicherheitsaudits.",
		"es": "Los registros de flujo proporcionan visibilidad sobre los patrones de tráfico de red y ayudan en la auditoría de seguridad.",
		"fr": "Les journaux de flux fournissent une visibilité sur les modèles de trafic réseau et aident à l'audit de sécurité.",
		"pt": "Logs de fluxo fornecem visibilidade sobre padrões de tráfego de rede e ajudam na auditoria de segurança."
	},
	"recommendation": {
		"en": "Add an alicloud_vpc_flow_log resource with resource_id referencing the VPC.",
		"zh": "添加 alicloud_vpc_flow_log 资源，并将 resource_id 指向该 VPC。",
		"ja": "VPC を参照する resource_id を持つ alicloud_vpc_flow_log リソースを追加します。",
		"de": "Fügen Sie eine alicloud_vpc_flow_log-Ressource mit resource_id hinzu, die auf das VPC verweist.",
		"es": "Agregue un recurso alicloud_vpc_flow_log con resource_id que haga referencia al VPC.",
		"fr": "Ajoutez une ressource alicloud_vpc_flow_log avec resource_id référençant le VPC.",
		"pt": "Adicione um recurso alicloud_vpc_flow_log com resource_id referenciando o VPC."
	},
	"resource_types": ["alicloud_vpc", "alicloud_vpc_flow_log"],
	"iac_type": "terraform"
}

vpc_count := count(tf.resources_by_type("alicloud_vpc"))

vpc_flow_log_count := count([name |
	some name, flow_log in tf.resources_by_type("alicloud_vpc_flow_log")
	resource_type := tf.get_attribute(flow_log, "resource_type", "VPC")
	resource_type == "VPC"
])

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_vpc")
	vpc_flow_log_count < vpc_count
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_vpc.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
