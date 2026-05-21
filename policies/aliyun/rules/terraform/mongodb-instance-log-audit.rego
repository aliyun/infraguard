package infraguard.rules.terraform.mongodb_instance_log_audit

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mongodb-instance-log-audit",
	"severity": "medium",
	"name": {
		"en": "MongoDB Instance Audit Logging Enabled",
		"zh": "MongoDB 实例开启审计日志",
		"ja": "MongoDB インスタンスログ監査が有効",
		"de": "MongoDB-Instanz Protokollprüfung aktiviert",
		"es": "Auditoría de Registro de Instancia MongoDB Habilitada",
		"fr": "Audit de Journal d'Instance MongoDB Activé",
		"pt": "Auditoria de Log de Instância MongoDB Habilitada"
	},
	"description": {
		"en": "MongoDB instances should have audit logging enabled for security monitoring.",
		"zh": "MongoDB 实例应开启审计日志以进行安全监控。",
		"ja": "MongoDB インスタンスで監査ログ記録が有効になっていることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen Protokollprüfung aktiviert haben.",
		"es": "Garantiza que las instancias MongoDB tengan auditoría de registro habilitada.",
		"fr": "Garantit que les instances MongoDB ont l'audit de journalisation activé.",
		"pt": "Garante que as instâncias MongoDB tenham auditoria de registro habilitada."
	},
	"reason": {
		"en": "The MongoDB instance does not have audit logging enabled.",
		"zh": "MongoDB 实例未开启审计日志。",
		"ja": "監査ログは、セキュリティ監視とコンプライアンス監査にとって重要です。",
		"de": "Prüfprotokolle sind entscheidend für die Sicherheitsüberwachung und Compliance-Prüfung.",
		"es": "Los registros de auditoría son críticos para el monitoreo de seguridad y la auditoría de cumplimiento.",
		"fr": "Les journaux d'audit sont essentiels pour la surveillance de la sécurité et l'audit de conformité.",
		"pt": "Os registros de auditoria são críticos para monitoramento de segurança e auditoria de conformidade."
	},
	"recommendation": {
		"en": "Set audit_status to 'enable' for the MongoDB instance.",
		"zh": "为 MongoDB 实例将 audit_status 设置为 'enable'。",
		"ja": "MongoDB インスタンスの監査ログ記録を有効にします。",
		"de": "Aktivieren Sie die Protokollprüfung für die MongoDB-Instanz.",
		"es": "Habilite la auditoría de registro para la instancia MongoDB.",
		"fr": "Activez l'audit de journalisation pour l'instance MongoDB.",
		"pt": "Habilite a auditoria de registro para a instância MongoDB."
	},
	"resource_types": ["alicloud_mongodb_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mongodb_instance")
	tf.get_attribute(resource, "audit_status", "disabled") != "enable"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mongodb_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
