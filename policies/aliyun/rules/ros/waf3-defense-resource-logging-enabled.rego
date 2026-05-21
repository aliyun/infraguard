package infraguard.rules.aliyun.waf3_defense_resource_logging_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "waf3-defense-resource-logging-enabled",
	"severity": "medium",
	"name": {
		"en": "WAF 3.0 Logging Enabled",
		"zh": "WAF 3.0 防护资源开启日志审计",
		"ja": "WAF 3.0 ログ記録が有効",
		"de": "WAF 3.0 Protokollierung aktiviert",
		"es": "Registro de WAF 3.0 Habilitado",
		"fr": "Journalisation WAF 3.0 Activée",
		"pt": "Registro do WAF 3.0 Habilitado"
	},
	"description": {
		"en": "Ensures that logging is enabled for resources protected by WAF 3.0.",
		"zh": "确保 WAF 3.0 防护的资源已开启日志审计。",
		"ja": "WAF 3.0 で保護されているリソースでログ記録が有効になっていることを確認します。",
		"de": "Stellt sicher, dass die Protokollierung für von WAF 3.0 geschützte Ressourcen aktiviert ist.",
		"es": "Garantiza que el registro esté habilitado para los recursos protegidos por WAF 3.0.",
		"fr": "Garantit que la journalisation est activée pour les ressources protégées par WAF 3.0.",
		"pt": "Garante que o registro esteja habilitado para recursos protegidos pelo WAF 3.0."
	},
	"reason": {
		"en": "Logging is critical for tracking web attacks and security incidents.",
		"zh": "日志记录对于追踪网络攻击和安全事件至关重要。",
		"ja": "ログ記録は、Web 攻撃とセキュリティインシデントを追跡するために重要です。",
		"de": "Die Protokollierung ist entscheidend für die Verfolgung von Web-Angriffen und Sicherheitsvorfällen.",
		"es": "El registro es crítico para rastrear ataques web e incidentes de seguridad.",
		"fr": "La journalisation est essentielle pour suivre les attaques Web et les incidents de sécurité.",
		"pt": "O registro é crítico para rastrear ataques web e incidentes de segurança."
	},
	"recommendation": {
		"en": "Enable log service for the WAF 3.0 instance.",
		"zh": "为 WAF 3.0 实例开启日志服务。",
		"ja": "WAF 3.0 インスタンスのログサービスを有効にします。",
		"de": "Aktivieren Sie den Log-Service für die WAF 3.0-Instanz.",
		"es": "Habilite el servicio de registro para la instancia WAF 3.0.",
		"fr": "Activez le service de journalisation pour l'instance WAF 3.0.",
		"pt": "Habilite o serviço de registro para a instância WAF 3.0."
	},
	"resource_types": ["ALIYUN::WAF3::Instance"]
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "LogService", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::WAF3::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LogService"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
