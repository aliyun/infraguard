package infraguard.rules.terraform.apig_group_custom_trace_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "apig-group-custom-trace-enabled",
	"severity": "low",
	"name": {
		"en": "API Gateway Group Custom Trace Enabled",
		"zh": "API 分组自定义追踪启用",
		"ja": "API ゲートウェイグループカスタムトレースが有効",
		"de": "API Gateway Gruppe Benutzerdefinierte Verfolgung aktiviert",
		"es": "Rastreo Personalizado de Grupo de API Gateway Habilitado",
		"fr": "Traçage Personnalisé du Groupe API Gateway Activé",
		"pt": "Rastreamento Personalizado do Grupo API Gateway Habilitado"
	},
	"description": {
		"en": "Ensures API Gateway groups have custom tracing enabled.",
		"zh": "确保 API 网关分组启用了自定义追踪功能。",
		"ja": "API ゲートウェイグループでカスタムトレースが有効になっていることを確認します。",
		"de": "Stellt sicher, dass API Gateway-Gruppen benutzerdefinierte Verfolgung aktiviert haben.",
		"es": "Garantiza que los grupos de API Gateway tengan rastreo personalizado habilitado.",
		"fr": "Garantit que les groupes API Gateway ont le traçage personnalisé activé.",
		"pt": "Garante que os grupos do API Gateway tenham rastreamento personalizado habilitado."
	},
	"reason": {
		"en": "Custom tracing enables better debugging and performance analysis.",
		"zh": "自定义追踪可实现更好的调试和性能分析。",
		"ja": "カスタムトレースにより、より良いデバッグとパフォーマンス分析が可能になります。",
		"de": "Benutzerdefinierte Verfolgung ermöglicht besseres Debugging und Leistungsanalyse.",
		"es": "El rastreo personalizado permite un mejor depuración y análisis de rendimiento.",
		"fr": "Le traçage personnalisé permet un meilleur débogage et une meilleure analyse des performances.",
		"pt": "O rastreamento personalizado permite melhor depuração e análise de desempenho."
	},
	"recommendation": {
		"en": "Enable custom tracing for API Gateway groups.",
		"zh": "为 API 网关分组启用自定义追踪。",
		"ja": "API ゲートウェイグループのカスタムトレースを有効にします。",
		"de": "Aktivieren Sie benutzerdefinierte Verfolgung für API Gateway-Gruppen.",
		"es": "Habilite el rastreo personalizado para los grupos de API Gateway.",
		"fr": "Activez le traçage personnalisé pour les groupes API Gateway.",
		"pt": "Habilite o rastreamento personalizado para os grupos do API Gateway."
	},
	"resource_types": ["alicloud_api_gateway_group", "alicloud_api_gateway_tracing"],
	"iac_type": "terraform"
}

as_array(value) := value if is_array(value)

else := [value] if is_object(value)

else := []

references_group(value, group_name) if {
	value == group_name
}

references_group(value, group_name) if {
	value == sprintf("alicloud_api_gateway_group.%s", [group_name])
}

references_group(value, group_name) if {
	contains(value, sprintf("alicloud_api_gateway_group.%s.", [group_name]))
}

has_tracing_tag(resource) if {
	some tag in as_array(tf.get_attribute(resource, "tags", []))
	object.get(tag, "TracingEnabled", "") == "true"
}

has_tracing_config(group_name) if {
	some tracing in tf.resources_by_type("alicloud_api_gateway_tracing")
	references_group(tf.get_attribute(tracing, "group_id", ""), group_name)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_api_gateway_group")
	not has_tracing_tag(resource)
	not has_tracing_config(name)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_api_gateway_group.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
