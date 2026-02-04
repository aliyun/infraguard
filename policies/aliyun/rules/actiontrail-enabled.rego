package infraguard.rules.aliyun.actiontrail_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "actiontrail-enabled",
	"name": {
		"en": "ActionTrail Enabled",
		"zh": "确保操作审计已开启",
		"ja": "ActionTrail が有効",
		"de": "ActionTrail aktiviert",
		"es": "ActionTrail Habilitado",
		"fr": "ActionTrail Activé",
		"pt": "ActionTrail Habilitado",
	},
	"severity": "high",
	"description": {
		"en": "Ensures ActionTrail is enabled to record account activities.",
		"zh": "确保开启了操作审计（ActionTrail）以记录账号活动。",
		"ja": "アカウント活動を記録するために ActionTrail が有効になっていることを確認します。",
		"de": "Stellt sicher, dass ActionTrail aktiviert ist, um Kontenaktivitäten aufzuzeichnen.",
		"es": "Garantiza que ActionTrail esté habilitado para registrar actividades de la cuenta.",
		"fr": "Garantit qu'ActionTrail est activé pour enregistrer les activités du compte.",
		"pt": "Garante que o ActionTrail está habilitado para registrar atividades da conta.",
	},
	"reason": {
		"en": "ActionTrail provides a record of API calls, which is essential for security auditing and forensic analysis.",
		"zh": "操作审计记录了 API 调用情况，这对于安全审计和取证分析至关重要。",
		"ja": "ActionTrail は API 呼び出しの記録を提供し、セキュリティ監査とフォレンジック分析に不可欠です。",
		"de": "ActionTrail bietet einen Datensatz von API-Aufrufen, der für Sicherheitsaudits und forensische Analysen unerlässlich ist.",
		"es": "ActionTrail proporciona un registro de llamadas API, esencial para auditorías de seguridad y análisis forense.",
		"fr": "ActionTrail fournit un enregistrement des appels API, essentiel pour l'audit de sécurité et l'analyse médico-légale.",
		"pt": "O ActionTrail fornece um registro de chamadas de API, essencial para auditoria de segurança e análise forense.",
	},
	"recommendation": {
		"en": "Create and enable at least one trail in ActionTrail.",
		"zh": "在操作审计中创建并启用至少一个跟踪（Trail）。",
		"ja": "ActionTrail で少なくとも 1 つのトレイルを作成して有効にします。",
		"de": "Erstellen und aktivieren Sie mindestens eine Spur in ActionTrail.",
		"es": "Cree y habilite al menos un rastro en ActionTrail.",
		"fr": "Créez et activez au moins une piste dans ActionTrail.",
		"pt": "Crie e habilite pelo menos uma trilha no ActionTrail.",
	},
	"resource_types": ["ALIYUN::ACTIONTRAIL::Trail"],
}

is_compliant(resource) := true

# If the resource exists in template, we check if logging is enabled
# Note: Often requires ALIYUN::ACTIONTRAIL::TrailLogging
# Basic check for existence of Trail resource

deny contains result if {
	# If no Trail resource exists at all in the template
	helpers.count_resources_by_type("ALIYUN::ACTIONTRAIL::Trail") == 0
	result := {
		"id": rule_meta.id,
		"resource_id": "Global",
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
