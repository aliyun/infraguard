package infraguard.rules.aliyun.vpn_gateway_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:vpn-gateway-multi-zone",
	"name": {
		"en": "VPN Gateway Multi-Zone Deployment",
		"zh": "使用多可用区的 VPN 网关",
	},
	"severity": "medium",
	"description": {
		"en": "VPN Gateways should be configured with a disaster recovery VSwitch to support multi-zone availability.",
		"zh": "为 VPN 网关设置两个交换机，保障产品跨可用区的高可用性，视为合规。",
	},
	"reason": {
		"en": "The VPN Gateway is not configured with a disaster recovery VSwitch.",
		"zh": "VPN 网关未配置容灾交换机。",
	},
	"recommendation": {
		"en": "Configure DisasterRecoveryVSwitchId to enable dual-tunnel/multi-zone mode.",
		"zh": "配置 DisasterRecoveryVSwitchId 以启用双隧道/多可用区模式。",
	},
	"resource_types": ["ALIYUN::VPC::VpnGateway"],
}

# Check if instance is multi-zone
is_multi_zone(resource) if {
	# Check if DisasterRecoveryVSwitchId is present and not empty
	object.get(resource.Properties, "DisasterRecoveryVSwitchId", "") != ""
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DisasterRecoveryVSwitchId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
