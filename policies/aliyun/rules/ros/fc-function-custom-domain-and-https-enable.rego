package infraguard.rules.aliyun.fc_function_custom_domain_and_https_enable

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "fc-function-custom-domain-and-https-enable",
	"severity": "medium",
	"name": {
		"en": "FC Function Custom Domain HTTPS Check",
		"zh": "函数计算函数绑定到自定义域名且开启 https",
		"ja": "FC 関数のカスタムドメイン HTTPS チェック",
		"de": "FC-Funktion Benutzerdefinierte Domain HTTPS-Prüfung",
		"es": "Verificación HTTPS de Dominio Personalizado de Función FC",
		"fr": "Vérification HTTPS du Domaine Personnalisé de Fonction FC",
		"pt": "Verificação HTTPS de Domínio Personalizado de Função FC"
	},
	"description": {
		"en": "FC custom domains should have HTTPS enabled for secure communication.",
		"zh": "函数计算函数绑定的自定义域名已开启 HTTPS，视为合规。",
		"ja": "FC カスタムドメインは安全な通信のために HTTPS を有効にする必要があります。",
		"de": "FC-Benutzerdefinierte Domains sollten HTTPS für sichere Kommunikation aktiviert haben.",
		"es": "Los dominios personalizados FC deben tener HTTPS habilitado para comunicación segura.",
		"fr": "Les domaines personnalisés FC doivent avoir HTTPS activé pour une communication sécurisée.",
		"pt": "Os domínios personalizados FC devem ter HTTPS habilitado para comunicação segura."
	},
	"reason": {
		"en": "The FC custom domain does not have HTTPS enabled, which may expose traffic to security risks.",
		"zh": "函数计算自定义域名未开启 HTTPS，可能导致流量面临安全风险。",
		"ja": "FC カスタムドメインで HTTPS が有効になっていないため、トラフィックがセキュリティリスクにさらされる可能性があります。",
		"de": "Die FC-Benutzerdefinierte Domain hat HTTPS nicht aktiviert, was Datenverkehr Sicherheitsrisiken aussetzen kann.",
		"es": "El dominio personalizado FC no tiene HTTPS habilitado, lo que puede exponer el tráfico a riesgos de seguridad.",
		"fr": "Le domaine personnalisé FC n'a pas HTTPS activé, ce qui peut exposer le trafic à des risques de sécurité.",
		"pt": "O domínio personalizado FC não tem HTTPS habilitado, o que pode expor o tráfego a riscos de segurança."
	},
	"recommendation": {
		"en": "Enable HTTPS for the custom domain in the FC console or API.",
		"zh": "在函数计算控制台或 API 为自定义域名开启 HTTPS。",
		"ja": "FC コンソールまたは API でカスタムドメインの HTTPS を有効にします。",
		"de": "Aktivieren Sie HTTPS für die Benutzerdefinierte Domain in der FC-Konsole oder API.",
		"es": "Habilite HTTPS para el dominio personalizado en la consola FC o API.",
		"fr": "Activez HTTPS pour le domaine personnalisé dans la console FC ou l'API.",
		"pt": "Habilite HTTPS para o domínio personalizado no console FC ou API."
	},
	"resource_types": ["ALIYUN::FC::CustomDomain"]
}

# Check if custom domain has HTTPS enabled via protocol
has_https_enabled(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol == "HTTPS"
}

has_https_enabled(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol == "HTTP,HTTPS"
}

# Deny rule: Custom domains should have HTTPS enabled
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::CustomDomain")
	not has_https_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Protocol"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
