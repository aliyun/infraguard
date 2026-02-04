package infraguard.rules.aliyun.apig_group_custom_trace_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "apig-group-custom-trace-enabled",
	"name": {
		"en": "API Gateway Group Custom Trace Enabled",
		"zh": "API 分组自定义追踪启用",
		"ja": "API ゲートウェイグループカスタムトレースが有効",
		"de": "API Gateway Gruppe Benutzerdefinierte Verfolgung aktiviert",
		"es": "Rastreo Personalizado de Grupo de API Gateway Habilitado",
		"fr": "Traçage Personnalisé du Groupe API Gateway Activé",
		"pt": "Rastreamento Personalizado do Grupo API Gateway Habilitado",
	},
	"severity": "low",
	"description": {
		"en": "Ensures API Gateway groups have custom tracing enabled.",
		"zh": "确保 API 网关分组启用了自定义追踪功能。",
		"ja": "API ゲートウェイグループでカスタムトレースが有効になっていることを確認します。",
		"de": "Stellt sicher, dass API Gateway-Gruppen benutzerdefinierte Verfolgung aktiviert haben.",
		"es": "Garantiza que los grupos de API Gateway tengan rastreo personalizado habilitado.",
		"fr": "Garantit que les groupes API Gateway ont le traçage personnalisé activé.",
		"pt": "Garante que os grupos do API Gateway tenham rastreamento personalizado habilitado.",
	},
	"reason": {
		"en": "Custom tracing enables better debugging and performance analysis.",
		"zh": "自定义追踪可实现更好的调试和性能分析。",
		"ja": "カスタムトレースにより、より良いデバッグとパフォーマンス分析が可能になります。",
		"de": "Benutzerdefinierte Verfolgung ermöglicht besseres Debugging und Leistungsanalyse.",
		"es": "El rastreo personalizado permite un mejor depuración y análisis de rendimiento.",
		"fr": "Le traçage personnalisé permet un meilleur débogage et une meilleure analyse des performances.",
		"pt": "O rastreamento personalizado permite melhor depuração e análise de desempenho.",
	},
	"recommendation": {
		"en": "Enable custom tracing for API Gateway groups.",
		"zh": "为 API 网关分组启用自定义追踪。",
		"ja": "API ゲートウェイグループのカスタムトレースを有効にします。",
		"de": "Aktivieren Sie benutzerdefinierte Verfolgung für API Gateway-Gruppen.",
		"es": "Habilite el rastreo personalizado para los grupos de API Gateway.",
		"fr": "Activez le traçage personnalisé pour les groupes API Gateway.",
		"pt": "Habilite o rastreamento personalizado para os grupos do API Gateway.",
	},
	"resource_types": ["ALIYUN::ApiGateway::Group"],
}

deny contains result if {
	some group_name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Group")

	not has_tracing_enabled(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

has_tracing_enabled(resource) if {
	tags := helpers.get_property(resource, "Tags", [])
	some tag in tags
	tag.Key == "TracingEnabled"
	tag.Value == "true"
}

has_tracing_enabled(resource) if {
	some name, config in helpers.resources_by_type("ALIYUN::ApiGateway::Tracing")
	group_id := helpers.get_property(config, "GroupId", "")
	resource_group_id := helpers.get_property(resource, "GroupId", "")
	group_id == resource_group_id
}
