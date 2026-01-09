package infraguard.rules.aliyun.vpn_ipsec_connection_health_check_open

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:vpn-ipsec-connection-health-check-open",
	"name": {
		"en": "VPN IPsec Health Check Enabled",
		"zh": "VPN IPsec 连接开启健康检查"
	},
	"severity": "low",
	"description": {
		"en": "Ensures VPN IPsec connections have health checks enabled to detect tunnel failures.",
		"zh": "确保 VPN IPsec 连接开启了健康检查，以便及时发现隧道故障。"
	},
	"reason": {
		"en": "Health checks enable automatic failover and proactive monitoring of VPN stability.",
		"zh": "健康检查支持 VPN 稳定性的自动故障转移和主动监控。"
	},
	"recommendation": {
		"en": "Enable health checks for the IPsec connection.",
		"zh": "为 IPsec 连接开启健康检查。"
	},
	"resource_types": ["ALIYUN::VPC::VpnConnection"],
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
