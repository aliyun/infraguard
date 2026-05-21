package infraguard.rules.terraform.rds_instance_enabled_auditing

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "Set sql_collector_status to \"Enabled\" for the RDS instance.",
		"zh": "为 RDS 实例将 sql_collector_status 设置为 \"Enabled\"。",
		"ja": "RDS インスタンスの sql_collector_status を \"Enabled\" に設定します。",
		"de": "Setzen Sie sql_collector_status für die RDS-Instanz auf \"Enabled\".",
		"es": "Establezca sql_collector_status en \"Enabled\" para la instancia RDS.",
		"fr": "Définissez sql_collector_status sur \"Enabled\" pour l'instance RDS.",
		"pt": "Defina sql_collector_status como \"Enabled\" para a instância RDS."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	tf.get_attribute(resource, "sql_collector_status", "") != "Enabled"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
