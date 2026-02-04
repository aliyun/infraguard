package infraguard.rules.aliyun.vpn_gateway_enabled_ssl_vpn

import data.infraguard.helpers
import rego.v1

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
		"en": "Set EnableSsl to 'true' for the VPN Gateway.",
		"zh": "为 VPN 网关将 EnableSsl 设置为 'true'。",
		"ja": "VPN ゲートウェイの EnableSsl を 'true' に設定します。",
		"de": "Setzen Sie EnableSsl für das VPN-Gateway auf 'true'.",
		"es": "Establezca EnableSsl en 'true' para la puerta de enlace VPN.",
		"fr": "Définissez EnableSsl sur 'true' pour la passerelle VPN.",
		"pt": "Defina EnableSsl como 'true' para o Gateway VPN."
	},
	"resource_types": ["ALIYUN::VPC::VpnGateway"]
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "EnableSsl", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::VpnGateway")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EnableSsl"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
