package infraguard.rules.aliyun.fc_function_internet_and_custom_domain_enable

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "fc-function-internet-and-custom-domain-enable",
	"name": {
		"en": "FC Service Internet Access with Custom Domain",
		"zh": "函数计算服务允许访问公网且绑定到自定义域名",
	},
	"severity": "medium",
	"description": {
		"en": "FC services with internet access should be bound to custom domains for proper access control.",
		"zh": "函数计算服务在允许公网访问时绑定了自定义域名，视为合规。",
	},
	"reason": {
		"en": "The FC service allows internet access but may not have custom domains configured.",
		"zh": "函数计算服务允许访问公网，但可能未配置自定义域名。",
	},
	"recommendation": {
		"en": "Configure custom domains for FC services that need internet access.",
		"zh": "为需要公网访问的函数计算服务配置自定义域名。",
	},
	"resource_types": ["ALIYUN::FC::Service"],
}

# Check if service has internet access
has_internet_access(resource) if {
	helpers.get_property(resource, "InternetAccess", false) == true
}

# Check if any custom domain exists in the template (regardless of service)
has_custom_domain_in_template if {
	count(helpers.resources_by_type("ALIYUN::FC::CustomDomain")) > 0
}

# Deny rule: FC services with internet access should have custom domains in template
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::Service")
	has_internet_access(resource)
	not has_custom_domain_in_template
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
