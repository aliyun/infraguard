package infraguard.rules.terraform.api_gateway_group_https_policy_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "api-gateway-group-https-policy-check",
	"severity": "medium",
	"name": {
		"en": "API Gateway Group HTTPS Policy Check",
		"zh": "API 网关中 API 分组的 HTTPS 安全策略满足要求",
		"ja": "API ゲートウェイグループ HTTPS ポリシーチェック",
		"de": "API Gateway Gruppe HTTPS-Richtlinienprüfung",
		"es": "Verificación de Política HTTPS del Grupo de API Gateway",
		"fr": "Vérification de Politique HTTPS du Groupe API Gateway",
		"pt": "Verificação de Política HTTPS do Grupo API Gateway"
	},
	"description": {
		"en": "Ensures API Gateway groups have HTTPS security policy set correctly.",
		"zh": "确保 API 网关中的 API 分组设置的 HTTPS 安全策略在指定的参数列表中。",
		"ja": "API ゲートウェイグループで HTTPS セキュリティポリシーが正しく設定されていることを確認します。",
		"de": "Stellt sicher, dass API Gateway-Gruppen die HTTPS-Sicherheitsrichtlinie korrekt gesetzt haben.",
		"es": "Garantiza que los grupos de API Gateway tengan la política de seguridad HTTPS configurada correctamente.",
		"fr": "Garantit que les groupes API Gateway ont la politique de sécurité HTTPS définie correctement.",
		"pt": "Garante que os grupos do API Gateway tenham a política de segurança HTTPS configurada corretamente."
	},
	"reason": {
		"en": "Strong HTTPS policies ensure secure connections.",
		"zh": "强 HTTPS 策略确保连接安全。",
		"ja": "強力な HTTPS ポリシーにより、安全な接続が確保されます。",
		"de": "Starke HTTPS-Richtlinien gewährleisten sichere Verbindungen.",
		"es": "Las políticas HTTPS fuertes garantizan conexiones seguras.",
		"fr": "Des politiques HTTPS fortes garantissent des connexions sécurisées.",
		"pt": "Políticas HTTPS fortes garantem conexões seguras."
	},
	"recommendation": {
		"en": "Use TLS 1.2 or higher for HTTPS connections.",
		"zh": "使用 TLS 1.2 或更高版本进行 HTTPS 连接。",
		"ja": "HTTPS 接続には TLS 1.2 以降を使用します。",
		"de": "Verwenden Sie TLS 1.2 oder höher für HTTPS-Verbindungen.",
		"es": "Use TLS 1.2 o superior para conexiones HTTPS.",
		"fr": "Utilisez TLS 1.2 ou supérieur pour les connexions HTTPS.",
		"pt": "Use TLS 1.2 ou superior para conexões HTTPS."
	},
	"resource_types": ["alicloud_api_gateway_group", "alicloud_api_gateway_instance"],
	"iac_type": "terraform"
}

allowed_https_policies := {"HTTPS2_TLS1_2", "HTTPS2_TLS1_3"}

references_instance(value, instance_name) if {
	value == instance_name
}

references_instance(value, instance_name) if {
	value == sprintf("alicloud_api_gateway_instance.%s", [instance_name])
}

references_instance(value, instance_name) if {
	contains(value, sprintf("alicloud_api_gateway_instance.%s.", [instance_name]))
}

deny contains violation if {
	some group_name, group in tf.resources_by_type("alicloud_api_gateway_group")
	instance_id := tf.get_attribute(group, "instance_id", "")
	some instance_name, instance in tf.resources_by_type("alicloud_api_gateway_instance")
	references_instance(instance_id, instance_name)
	not tf.get_attribute(instance, "https_policy", "") in allowed_https_policies
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_api_gateway_group.%s", [group_name]),
		"violation_path": ["instance_id"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
