package infraguard.rules.aliyun.maxcompute_project_ip_whitelist_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:maxcompute-project-ip-whitelist-enabled",
	"name": {
		"en": "MaxCompute Project IP Whitelist Enabled",
		"zh": "MaxCompute 项目开启 IP 白名单"
	},
	"severity": "high",
	"description": {
		"en": "Ensures MaxCompute projects have an IP whitelist configured to restrict access.",
		"zh": "确保 MaxCompute 项目配置了 IP 白名单以限制访问。"
	},
	"reason": {
		"en": "Restricting access to trusted IPs prevents unauthorized data access over the network.",
		"zh": "限制可信 IP 访问可防止网络上的非授权数据访问。"
	},
	"recommendation": {
		"en": "Configure the IP whitelist for the MaxCompute project.",
		"zh": "为 MaxCompute 项目配置 IP 白名单。"
	},
	"resource_types": ["ALIYUN::MaxCompute::Project"],
}

is_compliant(resource) if {
	# Check for a property like 'IpWhiteList' in ROS
	helpers.has_property(resource, "IpWhiteList")
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MaxCompute::Project")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
