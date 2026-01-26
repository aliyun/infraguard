package infraguard.rules.aliyun.ess_scaling_configuration_enabled_internet_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ess-scaling-configuration-enabled-internet-check",
	"name": {
		"en": "ESS Scaling Configuration Internet Access Check",
		"zh": "ESS 伸缩配置公网访问检测",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that ESS scaling configurations do not enable public IP addresses for instances unless necessary.",
		"zh": "确保 ESS 伸缩配置未为实例开启公网 IP 地址，除非必要。",
	},
	"reason": {
		"en": "Enabling public IPs for all instances in a scaling group increases the attack surface.",
		"zh": "为伸缩组中的所有实例开启公网 IP 会增加攻击面。",
	},
	"recommendation": {
		"en": "Use internal IPs and a NAT gateway or SLB for internet access instead of public IPs on each instance.",
		"zh": "使用内网 IP 和 NAT 网关或 SLB 进行公网访问，而不是在每个实例上使用公网 IP。",
	},
	"resource_types": ["ALIYUN::ESS::ScalingConfiguration"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingConfiguration")
	helpers.get_property(resource, "InternetMaxBandwidthOut", 0) > 0
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "InternetMaxBandwidthOut"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
