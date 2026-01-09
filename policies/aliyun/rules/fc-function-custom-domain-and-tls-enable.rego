package infraguard.rules.aliyun.fc_function_custom_domain_and_tls_enable

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:fc-function-custom-domain-and-tls-enable",
	"name": {
		"en": "FC Function Custom Domain and TLS Enabled",
		"zh": "FC 函数自定义域名及 TLS 开启",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that custom domains for Function Compute functions have TLS enabled.",
		"zh": "确保函数计算函数的自定义域名已开启 TLS。",
	},
	"reason": {
		"en": "TLS encrypts traffic to your function, ensuring data confidentiality and integrity.",
		"zh": "TLS 对到函数的流量进行加密，确保数据机密性和完整性。",
	},
	"recommendation": {
		"en": "Configure an SSL certificate and enable TLS for the Function Compute custom domain.",
		"zh": "为函数计算自定义域名配置 SSL 证书并开启 TLS。",
	},
	"resource_types": ["ALIYUN::FC::CustomDomain"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::CustomDomain")

	# Conceptual check for TLS
	not helpers.has_property(resource, "CertConfig")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
