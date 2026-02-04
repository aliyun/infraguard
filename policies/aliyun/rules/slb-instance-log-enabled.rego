package infraguard.rules.aliyun.slb_instance_log_enabled

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "slb-instance-log-enabled",
	"name": {
		"en": "SLB Instance Logging Enabled",
		"zh": "SLB 实例开启访问日志",
		"ja": "SLB インスタンスでログ記録が有効",
		"de": "SLB-Instanz-Protokollierung aktiviert",
		"es": "Registro de Instancia SLB Habilitado",
		"fr": "Journalisation d'Instance SLB Activée",
		"pt": "Registro de Instância SLB Habilitado",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that access logging is enabled for the SLB instance.",
		"zh": "确保 SLB 实例开启了访问日志。",
		"ja": "SLB インスタンスでアクセスログ記録が有効になっていることを確認します。",
		"de": "Stellt sicher, dass Zugriffsprotokollierung für die SLB-Instanz aktiviert ist.",
		"es": "Garantiza que el registro de acceso esté habilitado para la instancia SLB.",
		"fr": "Garantit que la journalisation d'accès est activée pour l'instance SLB.",
		"pt": "Garante que o registro de acesso esteja habilitado para a instância SLB.",
	},
	"reason": {
		"en": "Access logs are essential for auditing traffic and troubleshooting connectivity and security issues.",
		"zh": "访问日志对于审计流量以及排查连接和安全问题至关重要。",
		"ja": "アクセスログは、トラフィックの監査、接続とセキュリティの問題のトラブルシューティングに不可欠です。",
		"de": "Zugriffsprotokolle sind unerlässlich für die Überwachung des Datenverkehrs und die Fehlerbehebung bei Verbindungs- und Sicherheitsproblemen.",
		"es": "Los registros de acceso son esenciales para auditar el tráfico y solucionar problemas de conectividad y seguridad.",
		"fr": "Les journaux d'accès sont essentiels pour auditer le trafic et résoudre les problèmes de connectivité et de sécurité.",
		"pt": "Os registros de acesso são essenciais para auditar tráfego e solucionar problemas de conectividade e segurança.",
	},
	"recommendation": {
		"en": "Enable access logging for the SLB instance.",
		"zh": "为 SLB 实例开启访问日志。",
		"ja": "SLB インスタンスでアクセスログ記録を有効にします。",
		"de": "Aktivieren Sie Zugriffsprotokollierung für die SLB-Instanz.",
		"es": "Habilite el registro de acceso para la instancia SLB.",
		"fr": "Activez la journalisation d'accès pour l'instance SLB.",
		"pt": "Habilite o registro de acesso para a instância SLB.",
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")

	# Conceptual check for logging
	not helpers.has_property(resource, "AccessLog")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
