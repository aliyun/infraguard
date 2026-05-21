package infraguard.rules.terraform.vpn_connection_master_slave_established

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "vpn-connection-master-slave-established",
	"severity": "medium",
	"name": {
		"en": "VPN Connection Dual Tunnel Established",
		"zh": "双隧道 VPN 网关主备隧道都已建立连接",
		"ja": "VPN 接続デュアルトンネル確立",
		"de": "VPN-Verbindung Dual-Tunnel eingerichtet",
		"es": "Conexión VPN Túnel Dual Establecido",
		"fr": "Connexion VPN Tunnel Double Établi",
		"pt": "Conexão VPN Túnel Duplo Estabelecido"
	},
	"description": {
		"en": "Use dual-tunnel VPN gateway and both master and slave tunnels are established with the peer.",
		"zh": "使用双隧道的 VPN 网关同时主备隧道都已和对端建立连接。",
		"ja": "デュアルトンネル VPN ゲートウェイを使用し、マスターとスレーブの両方のトンネルがピアと確立されています。",
		"de": "Verwenden Sie ein Dual-Tunnel-VPN-Gateway und beide Master- und Slave-Tunnel sind mit dem Peer eingerichtet.",
		"es": "Use una puerta de enlace VPN de túnel dual y ambos túneles maestro y esclavo están establecidos con el par.",
		"fr": "Utilisez une passerelle VPN à tunnel double et les tunnels maître et esclave sont établis avec le pair.",
		"pt": "Use um gateway VPN de túnel duplo e ambos os túneis mestre e escravo estão estabelecidos com o par."
	},
	"reason": {
		"en": "The VPN connection does not have dual tunnels configured.",
		"zh": "VPN 连接未配置双隧道。",
		"ja": "VPN 接続にデュアルトンネルが設定されていません。",
		"de": "Die VPN-Verbindung hat keine Dual-Tunnel-Konfiguration.",
		"es": "La conexión VPN no tiene túneles duales configurados.",
		"fr": "La connexion VPN n'a pas de tunnels doubles configurés.",
		"pt": "A conexão VPN não tem túneis duplos configurados."
	},
	"recommendation": {
		"en": "Configure the VPN connection with at least 2 tunnel_options_specification blocks for master and slave tunnels.",
		"zh": "使用至少 2 个 tunnel_options_specification 配置块来配置 VPN 连接的主备隧道。",
		"ja": "マスターとスレーブのトンネル用に、少なくとも 2 つの tunnel_options_specification ブロックで VPN 接続を設定します。",
		"de": "Konfigurieren Sie die VPN-Verbindung mit mindestens 2 tunnel_options_specification-Blöcken für Master- und Slave-Tunnel.",
		"es": "Configure la conexión VPN con al menos 2 bloques tunnel_options_specification para túneles maestro y esclavo.",
		"fr": "Configurez la connexion VPN avec au moins 2 blocs tunnel_options_specification pour les tunnels maître et esclave.",
		"pt": "Configure a conexão VPN com pelo menos 2 blocos tunnel_options_specification para túneis mestre e escravo."
	},
	"resource_types": ["alicloud_vpn_connection"],
	"iac_type": "terraform"
}

# Check if VPN connection has dual tunnels configured
# Note: A single block is stored as a map, multiple blocks as a list.
is_dual_tunnel(resource) if {
	tunnels := tf.get_attribute(resource, "tunnel_options_specification", [])
	not tf.is_unknown(tunnels)
	is_array(tunnels)
	count(tunnels) >= 2
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_vpn_connection")
	not is_dual_tunnel(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_vpn_connection.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
