package infraguard.rules.aliyun.fc_service_internet_access_disable

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:fc-service-internet-access-disable",
	"name": {
		"en": "FC Service Internet Access Disabled",
		"zh": "FC 服务禁用公网访问",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the Function Compute service has internet access disabled when it should only access internal resources.",
		"zh": "确保函数计算服务在仅需访问内网资源时已禁用公网访问。",
	},
	"reason": {
		"en": "Disabling internet access for FC services reduces the attack surface and potential for data exfiltration.",
		"zh": "为 FC 服务禁用公网访问可减少攻击面和潜在的数据泄露风险。",
	},
	"recommendation": {
		"en": "Disable internet access for the Function Compute service.",
		"zh": "为函数计算服务禁用公网访问。",
	},
	"resource_types": ["ALIYUN::FC::Service"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::Service")
	helpers.get_property(resource, "InternetAccess", true)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "InternetAccess"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
