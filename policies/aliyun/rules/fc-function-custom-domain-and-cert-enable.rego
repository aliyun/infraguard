package infraguard.rules.aliyun.fc_function_custom_domain_and_cert_enable

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "fc-function-custom-domain-and-cert-enable",
	"name": {
		"en": "FC Function Custom Domain Certificate Check",
		"zh": "函数计算函数绑定到自定义域名且上传证书",
	},
	"severity": "medium",
	"description": {
		"en": "FC custom domains should have SSL certificates configured for secure communication.",
		"zh": "函数计算函数绑定的自定义域名已上传 SSL 证书，视为合规。",
	},
	"reason": {
		"en": "The FC custom domain does not have an SSL certificate configured, which may expose traffic to security risks.",
		"zh": "函数计算自定义域名未配置 SSL 证书，可能导致流量面临安全风险。",
	},
	"recommendation": {
		"en": "Upload SSL certificates for the custom domain in the FC console or API.",
		"zh": "在函数计算控制台或 API 为自定义域名上传 SSL 证书。",
	},
	"resource_types": ["ALIYUN::FC::CustomDomain"],
}

# Check if custom domain has certificate configured
has_certificate(resource) if {
	cert_config := helpers.get_property(resource, "CertConfig", {})
	cert_config != {}
}

# Deny rule: Custom domains should have SSL certificates
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::CustomDomain")
	not has_certificate(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "CertConfig"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
