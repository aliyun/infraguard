package infraguard.rules.terraform.vpn_ipsec_connection_health_check_open

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "vpn-ipsec-connection-health-check-open",
	"severity": "low",
	"name": {
		"en": "VPN IPsec Health Check Enabled",
		"zh": "VPN IPsec 连接开启健康检查",
		"ja": "VPN IPsec ヘルスチェックが有効",
		"de": "VPN IPsec Health Check aktiviert",
		"es": "Verificación de Salud IPsec VPN Habilitada",
		"fr": "Vérification de Santé IPsec VPN Activée",
		"pt": "Verificação de Integridade IPsec VPN Habilitada"
	},
	"description": {
		"en": "Ensures VPN IPsec connections have health checks enabled to detect tunnel failures.",
		"zh": "确保 VPN IPsec 连接开启了健康检查，以便及时发现隧道故障。",
		"ja": "VPN IPsec 接続でトンネル障害を検出するためにヘルスチェックが有効になっていることを確認します。",
		"de": "Stellt sicher, dass VPN-IPsec-Verbindungen Health Checks aktiviert haben, um Tunnelausfälle zu erkennen.",
		"es": "Garantiza que las conexiones VPN IPsec tengan verificaciones de salud habilitadas para detectar fallas del túnel.",
		"fr": "Garantit que les connexions VPN IPsec ont des vérifications de santé activées pour détecter les défaillances du tunnel.",
		"pt": "Garante que as conexões VPN IPsec tenham verificações de integridade habilitadas para detectar falhas do túnel."
	},
	"reason": {
		"en": "Health checks enable automatic failover and proactive monitoring of VPN stability.",
		"zh": "健康检查支持 VPN 稳定性的自动故障转移和主动监控。",
		"ja": "ヘルスチェックにより、VPN の安定性の自動フェイルオーバーとプロアクティブな監視が可能になります。",
		"de": "Health Checks ermöglichen automatisches Failover und proaktive Überwachung der VPN-Stabilität.",
		"es": "Las verificaciones de salud permiten la conmutación por error automática y el monitoreo proactivo de la estabilidad VPN.",
		"fr": "Les vérifications de santé permettent le basculement automatique et la surveillance proactive de la stabilité VPN.",
		"pt": "As verificações de integridade permitem failover automático e monitoramento proativo da estabilidade VPN."
	},
	"recommendation": {
		"en": "Set health_check_config block with enable = true for the VPN connection.",
		"zh": "为 VPN 连接配置 health_check_config 块并设置 enable = true。",
		"ja": "VPN 接続の health_check_config ブロックで enable = true を設定します。",
		"de": "Setzen Sie den health_check_config-Block mit enable = true für die VPN-Verbindung.",
		"es": "Configure el bloque health_check_config con enable = true para la conexión VPN.",
		"fr": "Définissez le bloc health_check_config avec enable = true pour la connexion VPN.",
		"pt": "Defina o bloco health_check_config com enable = true para a conexão VPN."
	},
	"resource_types": ["alicloud_vpn_connection"],
	"iac_type": "terraform"
}

as_array(value) := value if is_array(value)

else := [value] if is_object(value)

else := []

is_health_check_enabled(resource) if {
	configs := as_array(tf.get_attribute(resource, "health_check_config", []))
	some config in configs
	tf.get_attribute(config, "enable", false) == true
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_vpn_connection")
	not is_health_check_enabled(resource)
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
