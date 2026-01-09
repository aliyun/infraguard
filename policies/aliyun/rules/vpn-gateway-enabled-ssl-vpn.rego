package infraguard.rules.aliyun.vpn_gateway_enabled_ssl_vpn

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:vpn-gateway-enabled-ssl-vpn",
	"name": {
		"en": "VPN Gateway SSL-VPN Enabled",
		"zh": "VPN 网关开启 SSL-VPN"
	},
	"severity": "low",
	"description": {
		"en": "Ensures the VPN gateway has SSL-VPN enabled for secure client access.",
		"zh": "确保 VPN 网关开启了 SSL-VPN，以便客户端安全访问。"
	},
	"reason": {
		"en": "SSL-VPN provides a secure way for remote users to access internal network resources.",
		"zh": "SSL-VPN 为远程用户访问内部网络资源提供了一种安全的方式。"
	},
	"recommendation": {
		"en": "Set EnableSsl to 'true' for the VPN Gateway.",
		"zh": "为 VPN 网关将 EnableSsl 设置为 'true'。"
	},
	"resource_types": ["ALIYUN::VPC::VpnGateway"],
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
