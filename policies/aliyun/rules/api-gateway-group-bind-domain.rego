package infraguard.rules.aliyun.api_gateway_group_bind_domain

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "api-gateway-group-bind-domain",
	"name": {
		"en": "API Gateway Group Bind Domain",
		"zh": "API 网关中 API 分组绑定自定义域名",
		"ja": "API ゲートウェイグループのドメインバインド",
		"de": "API-Gateway-Gruppe Domain binden",
		"es": "Vincular Dominio del Grupo de API Gateway",
		"fr": "Lier le Domaine du Groupe API Gateway",
		"pt": "Vincular Domínio do Grupo de API Gateway"
	},
	"severity": "medium",
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
	"resource_types": ["ALIYUN::ApiGateway::Group"],
}

deny contains result if {
	some group_name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Group")

	not has_custom_domain_bound(group_name, resource)

	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

has_custom_domain_bound(group_name, group_resource) if {
	some domain_name, domain_resource in helpers.resources_by_type("ALIYUN::ApiGateway::CustomDomain")
	bound_group_id := helpers.get_property(domain_resource, "GroupId", "")
	group_id := helpers.get_property(group_resource, "GroupId", "")

	# Handle direct string match
	bound_group_id == group_id
}

has_custom_domain_bound(group_name, group_resource) if {
	some domain_name, domain_resource in helpers.resources_by_type("ALIYUN::ApiGateway::CustomDomain")
	bound_group_id := helpers.get_property(domain_resource, "GroupId", "")

	# Handle Fn::GetAtt reference - check if it references the group
	helpers.is_get_att_referencing(bound_group_id, group_name)
}
