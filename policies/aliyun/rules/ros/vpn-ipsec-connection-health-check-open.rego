package infraguard.rules.aliyun.vpn_ipsec_connection_health_check_open

import data.infraguard.helpers
import rego.v1

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
		"en": "Enable health checks for the IPsec connection.",
		"zh": "为 IPsec 连接开启健康检查。",
		"ja": "IPsec 接続のヘルスチェックを有効にします。",
		"de": "Aktivieren Sie Health Checks für die IPsec-Verbindung.",
		"es": "Habilite las verificaciones de salud para la conexión IPsec.",
		"fr": "Activez les vérifications de santé pour la connexion IPsec.",
		"pt": "Habilite verificações de integridade para a conexão IPsec."
	},
	"resource_types": ["ALIYUN::VPC::VpnConnection"]
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "HealthCheckConfig", {}).Enable)
}

# Note: Properties might vary between IpsecConnection and IpsecServer in ROS.
# Assuming ALIYUN::VPC::IpsecConnection for most tunnel checks.
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::VpnConnection")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "HealthCheckConfig", "Enable"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
