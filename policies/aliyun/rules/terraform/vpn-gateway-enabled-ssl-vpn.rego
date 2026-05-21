package infraguard.rules.terraform.vpn_gateway_enabled_ssl_vpn

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "vpn-gateway-enabled-ssl-vpn",
	"severity": "low",
	"name": {
		"en": "VPN Gateway SSL-VPN Enabled",
		"zh": "VPN 网关开启 SSL-VPN",
		"ja": "VPN ゲートウェイ SSL-VPN が有効",
		"de": "VPN-Gateway SSL-VPN aktiviert",
		"es": "SSL-VPN de Puerta de Enlace VPN Habilitado",
		"fr": "SSL-VPN de Passerelle VPN Activé",
		"pt": "SSL-VPN do Gateway VPN Habilitado"
	},
	"description": {
		"en": "Ensures the VPN gateway has SSL-VPN enabled for secure client access.",
		"zh": "确保 VPN 网关开启了 SSL-VPN，以便客户端安全访问。",
		"ja": "VPN ゲートウェイでクライアントアクセスを安全にするために SSL-VPN が有効になっていることを確認します。",
		"de": "Stellt sicher, dass das VPN-Gateway SSL-VPN für sicheren Client-Zugriff aktiviert hat.",
		"es": "Garantiza que la puerta de enlace VPN tenga SSL-VPN habilitado para acceso seguro del cliente.",
		"fr": "Garantit que la passerelle VPN a SSL-VPN activé pour un accès client sécurisé.",
		"pt": "Garante que o gateway VPN tenha SSL-VPN habilitado para acesso seguro do cliente."
	},
	"reason": {
		"en": "SSL-VPN provides a secure way for remote users to access internal network resources.",
		"zh": "SSL-VPN 为远程用户访问内部网络资源提供了一种安全的方式。",
		"ja": "SSL-VPN は、リモートユーザーが内部ネットワークリソースにアクセスするための安全な方法を提供します。",
		"de": "SSL-VPN bietet eine sichere Möglichkeit für Remote-Benutzer, auf interne Netzwerkressourcen zuzugreifen.",
		"es": "SSL-VPN proporciona una forma segura para que los usuarios remotos accedan a los recursos de red internos.",
		"fr": "SSL-VPN fournit un moyen sécurisé pour les utilisateurs distants d'accéder aux ressources réseau internes.",
		"pt": "SSL-VPN fornece uma maneira segura para usuários remotos acessarem recursos de rede internos."
	},
	"recommendation": {
		"en": "Set ssl_vpn to 'enable' for the VPN Gateway.",
		"zh": "为 VPN 网关将 ssl_vpn 设置为 'enable'。",
		"ja": "VPN ゲートウェイの ssl_vpn を 'enable' に設定します。",
		"de": "Setzen Sie ssl_vpn für das VPN-Gateway auf 'enable'.",
		"es": "Establezca ssl_vpn en 'enable' para la puerta de enlace VPN.",
		"fr": "Définissez ssl_vpn sur 'enable' pour la passerelle VPN.",
		"pt": "Defina ssl_vpn como 'enable' para o Gateway VPN."
	},
	"resource_types": ["alicloud_vpn_gateway"],
	"iac_type": "terraform"
}

is_ssl_vpn_enabled(resource) if {
	value := tf.get_attribute(resource, "ssl_vpn", "")
	not tf.is_unknown(value)
	value == "enable"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_vpn_gateway")
	not is_ssl_vpn_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_vpn_gateway.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
