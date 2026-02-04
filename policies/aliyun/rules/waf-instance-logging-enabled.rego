package infraguard.rules.aliyun.waf_instance_logging_enabled

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "waf-instance-logging-enabled",
	"severity": "medium",
	"name": {
		"en": "WAF Instance Logging Enabled",
		"zh": "WAF 实例开启日志",
		"ja": "WAF インスタンスログが有効",
		"de": "WAF-Instanz Protokollierung aktiviert",
		"es": "Registro de Instancia WAF Habilitado",
		"fr": "Journalisation d'Instance WAF Activée",
		"pt": "Registro de Instância WAF Habilitado"
	},
	"description": {
		"en": "Ensures that logging is enabled for the WAF instance for auditing and security analysis.",
		"zh": "确保 WAF 实例开启了日志，以便进行审计和安全分析。",
		"ja": "監査とセキュリティ分析のために WAF インスタンスでログ記録が有効になっていることを確認します。",
		"de": "Stellt sicher, dass die Protokollierung für die WAF-Instanz für die Überwachung und Sicherheitsanalyse aktiviert ist.",
		"es": "Garantiza que el registro esté habilitado para la instancia WAF para auditoría y análisis de seguridad.",
		"fr": "Garantit que la journalisation est activée pour l'instance WAF pour l'audit et l'analyse de sécurité.",
		"pt": "Garante que o registro esteja habilitado para a instância WAF para auditoria e análise de segurança."
	},
	"reason": {
		"en": "WAF logs provide critical information about web attacks and traffic patterns.",
		"zh": "WAF 日志提供了关于 Web 攻击和流量模式的关键信息。",
		"ja": "WAF ログは、Web 攻撃とトラフィックパターンに関する重要な情報を提供します。",
		"de": "WAF-Protokolle liefern wichtige Informationen über Web-Angriffe und Verkehrsmuster.",
		"es": "Los registros WAF proporcionan información crítica sobre ataques web y patrones de tráfico.",
		"fr": "Les journaux WAF fournissent des informations critiques sur les attaques Web et les modèles de trafic.",
		"pt": "Os registros WAF fornecem informações críticas sobre ataques web e padrões de tráfego."
	},
	"recommendation": {
		"en": "Enable logging for the WAF instance.",
		"zh": "为 WAF 实例开启日志。",
		"ja": "WAF インスタンスのログ記録を有効にします。",
		"de": "Aktivieren Sie die Protokollierung für die WAF-Instanz.",
		"es": "Habilite el registro para la instancia WAF.",
		"fr": "Activez la journalisation pour l'instance WAF.",
		"pt": "Habilite o registro para a instância WAF."
	},
	"resource_types": ["ALIYUN::WAF3::Instance", "ALIYUN::WAF::Instance"]
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::WAF::Instance", "ALIYUN::WAF3::Instance"])

	# Conceptual check for logging
	not helpers.has_property(resource, "LogConfig")
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
