package infraguard.rules.aliyun.fc_function_custom_domain_and_cert_enable

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "fc-function-custom-domain-and-cert-enable",
	"severity": "medium",
	"name": {
		"en": "FC Function Custom Domain Certificate Check",
		"zh": "函数计算函数绑定到自定义域名且上传证书",
		"ja": "FC 関数カスタムドメイン証明書チェック",
		"de": "FC-Funktion Benutzerdefinierte Domäne Zertifikatsprüfung",
		"es": "Verificación de Certificado de Dominio Personalizado de Función FC",
		"fr": "Vérification du Certificat de Domaine Personnalisé de Fonction FC",
		"pt": "Verificação de Certificado de Domínio Personalizado de Função FC"
	},
	"description": {
		"en": "FC custom domains should have SSL certificates configured for secure communication.",
		"zh": "函数计算函数绑定的自定义域名已上传 SSL 证书，视为合规。",
		"ja": "FC カスタムドメインは、安全な通信のために SSL 証明書を設定する必要があります。",
		"de": "FC-benutzerdefinierte Domänen sollten SSL-Zertifikate für sichere Kommunikation konfiguriert haben.",
		"es": "Los dominios personalizados FC deben tener certificados SSL configurados para comunicación segura.",
		"fr": "Les domaines personnalisés FC doivent avoir des certificats SSL configurés pour une communication sécurisée.",
		"pt": "Os domínios personalizados FC devem ter certificados SSL configurados para comunicação segura."
	},
	"reason": {
		"en": "The FC custom domain does not have an SSL certificate configured, which may expose traffic to security risks.",
		"zh": "函数计算自定义域名未配置 SSL 证书，可能导致流量面临安全风险。",
		"ja": "FC カスタムドメインに SSL 証明書が設定されていないため、トラフィックがセキュリティリスクにさらされる可能性があります。",
		"de": "Die FC-benutzerdefinierte Domäne hat kein SSL-Zertifikat konfiguriert, was den Datenverkehr Sicherheitsrisiken aussetzen kann.",
		"es": "El dominio personalizado FC no tiene un certificado SSL configurado, lo que puede exponer el tráfico a riesgos de seguridad.",
		"fr": "Le domaine personnalisé FC n'a pas de certificat SSL configuré, ce qui peut exposer le trafic à des risques de sécurité.",
		"pt": "O domínio personalizado FC não tem um certificado SSL configurado, o que pode expor o tráfego a riscos de segurança."
	},
	"recommendation": {
		"en": "Upload SSL certificates for the custom domain in the FC console or API.",
		"zh": "在函数计算控制台或 API 为自定义域名上传 SSL 证书。",
		"ja": "FC コンソールまたは API でカスタムドメインの SSL 証明書をアップロードします。",
		"de": "Laden Sie SSL-Zertifikate für die benutzerdefinierte Domäne in der FC-Konsole oder API hoch.",
		"es": "Cargue certificados SSL para el dominio personalizado en la consola FC o API.",
		"fr": "Téléchargez les certificats SSL pour le domaine personnalisé dans la console FC ou l'API.",
		"pt": "Faça upload de certificados SSL para o domínio personalizado no console FC ou API."
	},
	"resource_types": ["ALIYUN::FC::CustomDomain"]
}

# Check if custom domain has certificate configured
has_certificate(resource) if {
	cert_config := helpers.get_property(resource, "CertConfig", {})
	cert_config != {}
}

# Deny rule: Custom domains should have SSL certificates
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::CustomDomain")
	not has_certificate(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "CertConfig"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
