package infraguard.rules.aliyun.vpn_connection_master_slave_established

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "vpn-connection-master-slave-established",
	"name": {
		"en": "VPN Connection Dual Tunnel Established",
		"zh": "双隧道 VPN 网关主备隧道都已建立连接",
		"ja": "VPN 接続デュアルトンネル確立",
		"de": "VPN-Verbindung Dual-Tunnel eingerichtet",
		"es": "Conexión VPN Túnel Dual Establecido",
		"fr": "Connexion VPN Tunnel Double Établi",
		"pt": "Conexão VPN Túnel Duplo Estabelecido",
	},
	"severity": "medium",
	"description": {
		"en": "Use dual-tunnel VPN gateway and both master and slave tunnels are established with the peer.",
		"zh": "使用双隧道的 VPN 网关同时主备隧道都已和对端建立连接。",
		"ja": "デュアルトンネル VPN ゲートウェイを使用し、マスターとスレーブの両方のトンネルがピアと確立されています。",
		"de": "Verwenden Sie ein Dual-Tunnel-VPN-Gateway und beide Master- und Slave-Tunnel sind mit dem Peer eingerichtet.",
		"es": "Use una puerta de enlace VPN de túnel dual y ambos túneles maestro y esclavo están establecidos con el par.",
		"fr": "Utilisez une passerelle VPN à tunnel double et les tunnels maître et esclave sont établis avec le pair.",
		"pt": "Use um gateway VPN de túnel duplo e ambos os túneis mestre e escravo estão estabelecidos com o par.",
	},
	"reason": {
		"en": "The VPN connection does not have dual tunnels configured.",
		"zh": "VPN 连接未配置双隧道。",
		"ja": "VPN 接続にデュアルトンネルが設定されていません。",
		"de": "Die VPN-Verbindung hat keine Dual-Tunnel-Konfiguration.",
		"es": "La conexión VPN no tiene túneles duales configurados.",
		"fr": "La connexion VPN n'a pas de tunnels doubles configurés.",
		"pt": "A conexão VPN não tem túneis duplos configurados.",
	},
	"recommendation": {
		"en": "Configure the VPN connection with both master and slave tunnels using TunnelOptionsSpecification.",
		"zh": "使用 TunnelOptionsSpecification 配置 VPN 连接的主备隧道。",
		"ja": "TunnelOptionsSpecification を使用して、マスターとスレーブの両方のトンネルで VPN 接続を設定します。",
		"de": "Konfigurieren Sie die VPN-Verbindung mit Master- und Slave-Tunneln unter Verwendung von TunnelOptionsSpecification.",
		"es": "Configure la conexión VPN con túneles maestro y esclavo usando TunnelOptionsSpecification.",
		"fr": "Configurez la connexion VPN avec les tunnels maître et esclave en utilisant TunnelOptionsSpecification.",
		"pt": "Configure a conexão VPN com túneis mestre e escravo usando TunnelOptionsSpecification.",
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
