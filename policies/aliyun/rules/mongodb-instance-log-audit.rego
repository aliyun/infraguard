package infraguard.rules.aliyun.mongodb_instance_log_audit

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "mongodb-instance-log-audit",
	"severity": "medium",
	"name": {
		"en": "MongoDB Instance Log Audit Enabled",
		"zh": "MongoDB 实例开启操作日志审计",
		"ja": "MongoDB インスタンスログ監査が有効",
		"de": "MongoDB-Instanz Protokollprüfung aktiviert",
		"es": "Auditoría de Registro de Instancia MongoDB Habilitada",
		"fr": "Audit de Journal d'Instance MongoDB Activé",
		"pt": "Auditoria de Log de Instância MongoDB Habilitada"
	},
	"description": {
		"en": "Ensures MongoDB instances have audit logging enabled.",
		"zh": "确保 MongoDB 实例开启了操作日志审计。",
		"ja": "MongoDB インスタンスで監査ログ記録が有効になっていることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen Protokollprüfung aktiviert haben.",
		"es": "Garantiza que las instancias MongoDB tengan auditoría de registro habilitada.",
		"fr": "Garantit que les instances MongoDB ont l'audit de journalisation activé.",
		"pt": "Garante que as instâncias MongoDB tenham auditoria de registro habilitada."
	},
	"reason": {
		"en": "Audit logs are critical for security monitoring and compliance auditing.",
		"zh": "审计日志对于安全监控和合规审计至关重要。",
		"ja": "監査ログは、セキュリティ監視とコンプライアンス監査にとって重要です。",
		"de": "Prüfprotokolle sind entscheidend für die Sicherheitsüberwachung und Compliance-Prüfung.",
		"es": "Los registros de auditoría son críticos para el monitoreo de seguridad y la auditoría de cumplimiento.",
		"fr": "Les journaux d'audit sont essentiels pour la surveillance de la sécurité et l'audit de conformité.",
		"pt": "Os registros de auditoria são críticos para monitoramento de segurança e auditoria de conformidade."
	},
	"recommendation": {
		"en": "Enable audit logging for the MongoDB instance.",
		"zh": "为 MongoDB 实例开启操作日志审计。",
		"ja": "MongoDB インスタンスの監査ログ記録を有効にします。",
		"de": "Aktivieren Sie die Protokollprüfung für die MongoDB-Instanz.",
		"es": "Habilite la auditoría de registro para la instancia MongoDB.",
		"fr": "Activez l'audit de journalisation pour l'instance MongoDB.",
		"pt": "Habilite a auditoria de registro para a instância MongoDB."
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"]
}

is_compliant(resource) if {
	audit_options := helpers.get_property(resource, "AuditPolicyOptions", {})
	status := object.get(audit_options, "AuditStatus", "disabled")
	status == "enable"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MONGODB::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AuditPolicyOptions", "AuditStatus"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
