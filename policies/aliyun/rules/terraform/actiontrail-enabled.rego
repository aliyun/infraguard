package infraguard.rules.terraform.actiontrail_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "actiontrail-enabled",
	"severity": "high",
	"name": {
		"en": "ActionTrail Enabled",
		"zh": "确保操作审计已开启",
		"ja": "ActionTrail が有効",
		"de": "ActionTrail aktiviert",
		"es": "ActionTrail Habilitado",
		"fr": "ActionTrail Activé",
		"pt": "ActionTrail Habilitado"
	},
	"description": {
		"en": "Ensures ActionTrail is enabled to record account activities.",
		"zh": "确保开启了操作审计（ActionTrail）以记录账号活动。",
		"ja": "アカウント活動を記録するために ActionTrail が有効になっていることを確認します。",
		"de": "Stellt sicher, dass ActionTrail aktiviert ist, um Kontenaktivitäten aufzuzeichnen.",
		"es": "Garantiza que ActionTrail esté habilitado para registrar actividades de la cuenta.",
		"fr": "Garantit qu'ActionTrail est activé pour enregistrer les activités du compte.",
		"pt": "Garante que o ActionTrail está habilitado para registrar atividades da conta."
	},
	"reason": {
		"en": "ActionTrail provides a record of API calls, which is essential for security auditing and forensic analysis.",
		"zh": "操作审计记录了 API 调用情况，这对于安全审计和取证分析至关重要。",
		"ja": "ActionTrail は API 呼び出しの記録を提供し、セキュリティ監査とフォレンジック分析に不可欠です。",
		"de": "ActionTrail bietet einen Datensatz von API-Aufrufen, der für Sicherheitsaudits und forensische Analysen unerlässlich ist.",
		"es": "ActionTrail proporciona un registro de llamadas API, esencial para auditorías de seguridad y análisis forense.",
		"fr": "ActionTrail fournit un enregistrement des appels API, essentiel pour l'audit de sécurité et l'analyse médico-légale.",
		"pt": "O ActionTrail fornece um registro de chamadas de API, essencial para auditoria de segurança e análise forense."
	},
	"recommendation": {
		"en": "Create at least one alicloud_actiontrail_trail resource in Terraform.",
		"zh": "在 Terraform 中创建至少一个 alicloud_actiontrail_trail 资源。",
		"ja": "Terraform で少なくとも 1 つの alicloud_actiontrail_trail リソースを作成します。",
		"de": "Erstellen Sie mindestens eine alicloud_actiontrail_trail-Ressource in Terraform.",
		"es": "Cree al menos un recurso alicloud_actiontrail_trail en Terraform.",
		"fr": "Créez au moins une ressource alicloud_actiontrail_trail dans Terraform.",
		"pt": "Crie pelo menos um recurso alicloud_actiontrail_trail no Terraform."
	},
	"resource_types": ["alicloud_actiontrail_trail"],
	"iac_type": "terraform"
}

deny contains violation if {
	not tf.has_resource_type("alicloud_actiontrail_trail")
	violation := {
		"id": rule_meta.id,
		"resource_id": "Global",
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
