package infraguard.rules.terraform.api_gateway_group_log_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "api-gateway-group-log-enabled",
	"severity": "medium",
	"name": {
		"en": "API Gateway Group Log Enabled",
		"zh": "为 API 分组设置调用日志存储",
		"ja": "API ゲートウェイグループログが有効",
		"de": "API Gateway Gruppe Log aktiviert",
		"es": "Registro de Grupo de API Gateway Habilitado",
		"fr": "Journal du Groupe API Gateway Activé",
		"pt": "Log do Grupo API Gateway Habilitado"
	},
	"description": {
		"en": "Ensures API Gateway groups have logging configured.",
		"zh": "确保 API 网关中 API 分组设置了调用日志存储。",
		"ja": "API ゲートウェイグループでログ記録が設定されていることを確認します。",
		"de": "Stellt sicher, dass API Gateway-Gruppen Protokollierung konfiguriert haben.",
		"es": "Garantiza que los grupos de API Gateway tengan registro configurado.",
		"fr": "Garantit que les groupes API Gateway ont la journalisation configurée.",
		"pt": "Garante que os grupos do API Gateway tenham registro configurado."
	},
	"reason": {
		"en": "Logging enables monitoring and troubleshooting of API usage.",
		"zh": "日志记录可实现 API 使用的监控和故障排除。",
		"ja": "ログ記録により、API 使用の監視とトラブルシューティングが可能になります。",
		"de": "Die Protokollierung ermöglicht die Überwachung und Fehlerbehebung der API-Nutzung.",
		"es": "El registro permite el monitoreo y la solución de problemas del uso de la API.",
		"fr": "La journalisation permet la surveillance et le dépannage de l'utilisation de l'API.",
		"pt": "O registro permite monitoramento e solução de problemas do uso da API."
	},
	"recommendation": {
		"en": "Enable logging for API Gateway groups.",
		"zh": "为 API 网关分组启用日志记录。",
		"ja": "API ゲートウェイグループのログ記録を有効にします。",
		"de": "Aktivieren Sie die Protokollierung für API Gateway-Gruppen.",
		"es": "Habilite el registro para los grupos de API Gateway.",
		"fr": "Activez la journalisation pour les groupes API Gateway.",
		"pt": "Habilite o registro para os grupos do API Gateway."
	},
	"resource_types": ["alicloud_api_gateway_group", "alicloud_api_gateway_log_config"],
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

has_log_tag(resource) if {
	some tag in as_array(tf.get_attribute(resource, "tags", []))
	object.get(tag, "LogEnabled", "") == "true"
}

has_log_config(group_name) if {
	some log_resource in tf.resources_by_type("alicloud_api_gateway_log_config")
	references_group(tf.get_attribute(log_resource, "group_id", ""), group_name)
	tf.get_attribute(log_resource, "log_store", "") != ""
}

has_log_config(group_name) if {
	some log_resource in tf.resources_by_type("alicloud_api_gateway_log_config")
	references_group(tf.get_attribute(log_resource, "group_id", ""), group_name)
	tf.get_attribute(log_resource, "sls_log_store", "") != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_api_gateway_group")
	not has_log_tag(resource)
	not has_log_config(name)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_api_gateway_group.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
