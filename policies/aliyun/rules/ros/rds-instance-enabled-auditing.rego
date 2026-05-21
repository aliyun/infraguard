package infraguard.rules.aliyun.rds_instance_enabled_auditing

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rds-instance-enabled-auditing",
	"severity": "medium",
	"name": {
		"en": "RDS Instance Auditing Enabled",
		"zh": "RDS 实例开启 SQL 审计",
		"ja": "RDS インスタンスで監査が有効",
		"de": "RDS-Instanz-Überwachung aktiviert",
		"es": "Auditoría de Instancia RDS Habilitada",
		"fr": "Audit d'Instance RDS Activé",
		"pt": "Auditoria de Instância RDS Habilitada"
	},
	"description": {
		"en": "Ensures RDS instances have SQL auditing enabled.",
		"zh": "确保 RDS 实例开启了 SQL 审计。",
		"ja": "RDS インスタンスで SQL 監査が有効になっていることを確認します。",
		"de": "Stellt sicher, dass RDS-Instanzen SQL-Überwachung aktiviert haben.",
		"es": "Garantiza que las instancias RDS tengan auditoría SQL habilitada.",
		"fr": "Garantit que les instances RDS ont l'audit SQL activé.",
		"pt": "Garante que as instâncias RDS tenham auditoria SQL habilitada."
	},
	"reason": {
		"en": "SQL auditing helps track database activities and investigate security incidents.",
		"zh": "SQL 审计有助于跟踪数据库活动并调查安全事件。",
		"ja": "SQL 監査は、データベース活動を追跡し、セキュリティインシデントを調査するのに役立ちます。",
		"de": "SQL-Überwachung hilft dabei, Datenbankaktivitäten zu verfolgen und Sicherheitsvorfälle zu untersuchen.",
		"es": "La auditoría SQL ayuda a rastrear las actividades de la base de datos e investigar incidentes de seguridad.",
		"fr": "L'audit SQL aide à suivre les activités de la base de données et à enquêter sur les incidents de sécurité.",
		"pt": "A auditoria SQL ajuda a rastrear atividades do banco de dados e investigar incidentes de segurança."
	},
	"recommendation": {
		"en": "Enable SQL Collector for the RDS instance.",
		"zh": "为 RDS 实例开启 SQL 审计（SQL Collector）。",
		"ja": "RDS インスタンスで SQL Collector を有効にします。",
		"de": "Aktivieren Sie SQL Collector für die RDS-Instanz.",
		"es": "Habilite SQL Collector para la instancia RDS.",
		"fr": "Activez SQL Collector pour l'instance RDS.",
		"pt": "Habilite SQL Collector para a instância RDS."
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"]
}

is_compliant(resource) if {
	helpers.get_property(resource, "SQLCollectorStatus", "Disabled") == "Enable"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SQLCollectorStatus"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
