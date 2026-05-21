package infraguard.rules.terraform.api_gateway_group_enabled_ssl

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "api-gateway-group-enabled-ssl",
	"severity": "medium",
	"name": {
		"en": "API Gateway Group SSL Enabled",
		"zh": "API 网关分组开启 SSL",
		"ja": "API ゲートウェイグループで SSL が有効",
		"de": "API-Gateway-Gruppe SSL aktiviert",
		"es": "SSL de Grupo de API Gateway Habilitado",
		"fr": "SSL du Groupe API Gateway Activé",
		"pt": "SSL do Grupo de API Gateway Habilitado"
	},
	"description": {
		"en": "Ensures that SSL is enabled for API Gateway groups.",
		"zh": "确保 API 网关分组开启了 SSL。",
		"ja": "API ゲートウェイグループで SSL が有効になっていることを確認します。",
		"de": "Stellt sicher, dass SSL für API-Gateway-Gruppen aktiviert ist.",
		"es": "Garantiza que SSL esté habilitado para los grupos de API Gateway.",
		"fr": "Garantit que SSL est activé pour les groupes API Gateway.",
		"pt": "Garante que SSL esteja habilitado para grupos de API Gateway."
	},
	"reason": {
		"en": "SSL encrypts traffic between clients and the API Gateway, ensuring data confidentiality.",
		"zh": "SSL 对客户端和 API 网关之间的流量进行加密，确保数据机密性。",
		"ja": "SSL はクライアントと API ゲートウェイ間のトラフィックを暗号化し、データの機密性を確保します。",
		"de": "SSL verschlüsselt den Datenverkehr zwischen Clients und dem API-Gateway und gewährleistet die Vertraulichkeit der Daten.",
		"es": "SSL cifra el tráfico entre clientes y la API Gateway, garantizando la confidencialidad de los datos.",
		"fr": "SSL chiffre le trafic entre les clients et l'API Gateway, garantissant la confidentialité des données.",
		"pt": "SSL criptografa o tráfego entre clientes e o API Gateway, garantindo a confidencialidade dos dados."
	},
	"recommendation": {
		"en": "Configure an SSL certificate for the API Gateway group.",
		"zh": "为 API 网关分组配置 SSL 证书。",
		"ja": "API ゲートウェイグループに SSL 証明書を設定します。",
		"de": "Konfigurieren Sie ein SSL-Zertifikat für die API-Gateway-Gruppe.",
		"es": "Configure un certificado SSL para el grupo de API Gateway.",
		"fr": "Configurez un certificat SSL pour le groupe API Gateway.",
		"pt": "Configure um certificado SSL para o grupo de API Gateway."
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

has_ssl_certificate(domain) if {
	tf.get_attribute(domain, "certificate_body", "") != ""
	tf.get_attribute(domain, "certificate_private_key", "") != ""
}

has_ssl_certificate(domain) if {
	tf.get_attribute(domain, "certificate_id", "") != ""
}

has_ssl_enabled(group_name) if {
	some domain in tf.resources_by_type("alicloud_api_gateway_custom_domain")
	references_group(tf.get_attribute(domain, "group_id", ""), group_name)
	has_ssl_certificate(domain)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_api_gateway_group")
	not has_ssl_enabled(name)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_api_gateway_group.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
