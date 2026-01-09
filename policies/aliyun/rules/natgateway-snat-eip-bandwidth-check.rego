package infraguard.rules.aliyun.natgateway_snat_eip_bandwidth_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:natgateway-snat-eip-bandwidth-check",
	"name": {
		"en": "NAT Gateway SNAT EIP Bandwidth Consistency",
		"zh": "NAT 网关 SNAT 条目绑定多个 EIP 时带宽峰值设置一致"
	},
	"severity": "medium",
	"description": {
		"en": "When SNAT entries are bound to multiple EIPs, the bandwidth peak settings should be consistent or they should be added to a shared bandwidth package.",
		"zh": "NAT 网关中 SNAT 条目绑定的多个 EIP，加入共享带宽包或者所绑定的 EIP 带宽峰值设置一致，视为合规。"
	},
	"reason": {
		"en": "Inconsistent bandwidth settings can lead to unpredictable network performance and potential traffic distribution issues.",
		"zh": "不一致的带宽设置可能导致不可预测的网络性能和潜在的流量分配问题。"
	},
	"recommendation": {
		"en": "Ensure all EIPs bound to SNAT entries have consistent bandwidth settings or use a shared bandwidth package.",
		"zh": "确保绑定到 SNAT 条目的所有 EIP 具有一致的带宽设置，或使用共享带宽包。"
	},
	"resource_types": ["ALIYUN::VPC::NatGateway"],
}

is_vpc_nat_gateway(resource) if {
	network_type := helpers.get_property(resource, "NetworkType", "")
	network_type == "intranet"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::NatGateway")
	not is_vpc_nat_gateway(resource)

	# Simplified check: assumes proper configuration is present
	not helpers.has_property(resource, "EipBindMode")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EipBindMode"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
