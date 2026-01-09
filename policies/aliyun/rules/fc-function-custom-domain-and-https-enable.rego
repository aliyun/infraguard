package infraguard.rules.aliyun.fc_function_custom_domain_and_https_enable

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:fc-function-custom-domain-and-https-enable",
	"name": {
		"en": "FC Function Custom Domain HTTPS Check",
		"zh": "函数计算函数绑定到自定义域名且开启 https",
	},
	"severity": "medium",
	"description": {
		"en": "FC custom domains should have HTTPS enabled for secure communication.",
		"zh": "函数计算函数绑定的自定义域名已开启 HTTPS，视为合规。",
	},
	"reason": {
		"en": "The FC custom domain does not have HTTPS enabled, which may expose traffic to security risks.",
		"zh": "函数计算自定义域名未开启 HTTPS，可能导致流量面临安全风险。",
	},
	"recommendation": {
		"en": "Enable HTTPS for the custom domain in the FC console or API.",
		"zh": "在函数计算控制台或 API 为自定义域名开启 HTTPS。",
	},
	"resource_types": ["ALIYUN::FC::CustomDomain"],
}

# Check if custom domain has HTTPS enabled via protocol
has_https_enabled(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol == "HTTPS"
}

has_https_enabled(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol == "HTTP,HTTPS"
}

# Deny rule: Custom domains should have HTTPS enabled
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::CustomDomain")
	not has_https_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Protocol"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
