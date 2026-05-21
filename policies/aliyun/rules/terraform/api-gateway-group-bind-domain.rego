package infraguard.rules.terraform.api_gateway_group_bind_domain

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "api-gateway-group-bind-domain",
	"severity": "medium",
	"name": {
		"en": "API Gateway Group Bind Domain",
		"zh": "API 网关中 API 分组绑定自定义域名",
		"ja": "API ゲートウェイグループのドメインバインド",
		"de": "API-Gateway-Gruppe Domain binden",
		"es": "Vincular Dominio del Grupo de API Gateway",
		"fr": "Lier le Domaine du Groupe API Gateway",
		"pt": "Vincular Domínio do Grupo de API Gateway"
	},
	"description": {
		"en": "Ensures API Gateway groups have custom domains bound.",
		"zh": "确保 API 网关中的 API 分组绑定了自定义域名。",
		"ja": "API ゲートウェイグループにカスタムドメインがバインドされていることを確認します。",
		"de": "Stellt sicher, dass API-Gateway-Gruppen benutzerdefinierte Domains gebunden haben.",
		"es": "Garantiza que los grupos de API Gateway tengan dominios personalizados vinculados.",
		"fr": "Garantit que les groupes API Gateway ont des domaines personnalisés liés.",
		"pt": "Garante que os grupos de API Gateway tenham domínios personalizados vinculados."
	},
	"reason": {
		"en": "Custom domains provide better branding and control.",
		"zh": "自定义域名提供更好的品牌控制和可管理性。",
		"ja": "カスタムドメインはより優れたブランディングと制御を提供します。",
		"de": "Benutzerdefinierte Domains bieten besseres Branding und Kontrolle.",
		"es": "Los dominios personalizados proporcionan mejor marca y control.",
		"fr": "Les domaines personnalisés offrent un meilleur branding et contrôle.",
		"pt": "Os domínios personalizados fornecem melhor marca e controle."
	},
	"recommendation": {
		"en": "Bind custom domains to API Gateway groups.",
		"zh": "为 API 网关分组绑定自定义域名。",
		"ja": "API ゲートウェイグループにカスタムドメインをバインドします。",
		"de": "Binden Sie benutzerdefinierte Domains an API-Gateway-Gruppen.",
		"es": "Vincule dominios personalizados a grupos de API Gateway.",
		"fr": "Liez des domaines personnalisés aux groupes API Gateway.",
		"pt": "Vincule domínios personalizados a grupos de API Gateway."
	},
	"resource_types": ["alicloud_api_gateway_custom_domain", "alicloud_api_gateway_group"],
	"iac_type": "terraform"
}

references_group(value, group_name) if {
	value == group_name
}

references_group(value, group_name) if {
	value == sprintf("alicloud_api_gateway_group.%s", [group_name])
}

references_group(value, group_name) if {
	contains(value, sprintf("alicloud_api_gateway_group.%s.", [group_name]))
}

has_custom_domain_bound(group_name) if {
	some domain in tf.resources_by_type("alicloud_api_gateway_custom_domain")
	group_id := tf.get_attribute(domain, "group_id", "")
	references_group(group_id, group_name)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_api_gateway_group")
	not has_custom_domain_bound(name)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_api_gateway_group.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
