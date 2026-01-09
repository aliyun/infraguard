package infraguard.rules.aliyun.vpn_connection_master_slave_established

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:vpn-connection-master-slave-established",
	"name": {
		"en": "VPN Connection Dual Tunnel Established",
		"zh": "双隧道 VPN 网关主备隧道都已建立连接",
	},
	"severity": "medium",
	"description": {
		"en": "Use dual-tunnel VPN gateway and both master and slave tunnels are established with the peer.",
		"zh": "使用双隧道的 VPN 网关同时主备隧道都已和对端建立连接。",
	},
	"reason": {
		"en": "The VPN connection does not have dual tunnels configured.",
		"zh": "VPN 连接未配置双隧道。",
	},
	"recommendation": {
		"en": "Configure the VPN connection with both master and slave tunnels using TunnelOptionsSpecification.",
		"zh": "使用 TunnelOptionsSpecification 配置 VPN 连接的主备隧道。",
	},
	"resource_types": ["ALIYUN::VPC::VpnConnection"],
}

# Check if VPN connection has dual tunnels configured
is_dual_tunnel(resource) if {
	count(object.get(resource.Properties, "TunnelOptionsSpecification", [])) >= 2
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_dual_tunnel(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TunnelOptionsSpecification"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
