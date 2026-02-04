package infraguard.rules.aliyun.api_gateway_group_force_https

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "api-gateway-group-force-https",
	"name": {
		"en": "API Gateway Group Force HTTPS",
		"zh": "API 分组绑定独立域名并开启 Https 强制跳转",
		"ja": "API ゲートウェイグループの HTTPS 強制",
		"de": "API-Gateway-Gruppe HTTPS erzwingen",
		"es": "Forzar HTTPS del Grupo de API Gateway",
		"fr": "Forcer HTTPS du Groupe API Gateway",
		"pt": "Forçar HTTPS do Grupo de API Gateway"
	},
	"severity": "high",
	"description": {
		"en": "Ensures API Gateway groups with public custom domains have HTTPS force redirect enabled.",
		"zh": "检测网关分组下的所有公网独立域名是否都开启 HTTPS 强制跳转。",
		"ja": "パブリックカスタムドメインを持つ API ゲートウェイグループで HTTPS 強制リダイレクトが有効になっていることを確認します。",
		"de": "Stellt sicher, dass API-Gateway-Gruppen mit öffentlichen benutzerdefinierten Domains HTTPS-Force-Redirect aktiviert haben.",
		"es": "Garantiza que los grupos de API Gateway con dominios personalizados públicos tengan redirección forzada HTTPS habilitada.",
		"fr": "Garantit que les groupes API Gateway avec des domaines personnalisés publics ont la redirection HTTPS forcée activée.",
		"pt": "Garante que os grupos de API Gateway com domínios personalizados públicos tenham redirecionamento forçado HTTPS habilitado."
	},
	"reason": {
		"en": "HTTPS force redirect ensures all traffic is encrypted.",
		"zh": "HTTPS 强制跳转确保所有流量都经过加密。",
		"ja": "HTTPS 強制リダイレクトにより、すべてのトラフィックが暗号化されます。",
		"de": "HTTPS-Force-Redirect stellt sicher, dass der gesamte Datenverkehr verschlüsselt ist.",
		"es": "La redirección forzada HTTPS garantiza que todo el tráfico esté cifrado.",
		"fr": "La redirection HTTPS forcée garantit que tout le trafic est chiffré.",
		"pt": "O redirecionamento forçado HTTPS garante que todo o tráfego esteja criptografado."
	},
	"recommendation": {
		"en": "Enable HTTPS force redirect for all public domains.",
		"zh": "为所有公网域名启用 HTTPS 强制跳转。",
		"ja": "すべてのパブリックドメインで HTTPS 強制リダイレクトを有効にします。",
		"de": "Aktivieren Sie HTTPS-Force-Redirect für alle öffentlichen Domains.",
		"es": "Habilite la redirección forzada HTTPS para todos los dominios públicos.",
		"fr": "Activez la redirection HTTPS forcée pour tous les domaines publics.",
		"pt": "Habilite o redirecionamento forçado HTTPS para todos os domínios públicos."
	},
	"resource_types": ["ALIYUN::ApiGateway::Group"],
}

deny contains result if {
	some group_name, group_resource in helpers.resources_by_type("ALIYUN::ApiGateway::Group")

	some domain_resource in helpers.resources_by_type("ALIYUN::ApiGateway::CustomDomain")
	bound_group_id := helpers.get_property(domain_resource, "GroupId", "")

	# Check if domain is bound to this group (direct match via Ref)
	helpers.is_referencing(bound_group_id, group_name)

	domain_name := helpers.get_property(domain_resource, "DomainName", "")
	is_public_domain(domain_name)

	cert_body := helpers.get_property(domain_resource, "CertificateBody", "")
	cert_key := helpers.get_property(domain_resource, "CertificatePrivateKey", "")
	cert_body == ""
	cert_key == ""

	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties", "CustomDomains"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some group_name, group_resource in helpers.resources_by_type("ALIYUN::ApiGateway::Group")

	some domain_resource in helpers.resources_by_type("ALIYUN::ApiGateway::CustomDomain")
	bound_group_id := helpers.get_property(domain_resource, "GroupId", "")

	# Check if domain is bound to this group (Fn::GetAtt reference)
	helpers.is_get_att_referencing(bound_group_id, group_name)

	domain_name := helpers.get_property(domain_resource, "DomainName", "")
	is_public_domain(domain_name)

	cert_body := helpers.get_property(domain_resource, "CertificateBody", "")
	cert_key := helpers.get_property(domain_resource, "CertificatePrivateKey", "")
	cert_body == ""
	cert_key == ""

	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties", "CustomDomains"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

is_public_domain(domain) if {
	not contains(domain, ".internal.")
	not contains(domain, ".local")
}
