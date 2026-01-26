package infraguard.rules.aliyun.use_waf_instance_for_security_protection

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "use-waf-instance-for-security-protection",
	"name": {
		"en": "Use WAF for Security Protection",
		"zh": "使用 WEB 防火墙对网站或 APP 进行安全防护",
	},
	"severity": "high",
	"description": {
		"en": "WEB Application Firewall (WAF) should be used to protect websites and APPs from web-based attacks.",
		"zh": "使用 WEB 防火墙对网站或 APP 进行安全防护，视为合规。",
	},
	"reason": {
		"en": "The ALB instance does not have WAF enabled, leaving web assets vulnerable to attacks.",
		"zh": "ALB 实例未启用 WAF 防护，使 Web 资产容易受到攻击。",
	},
	"recommendation": {
		"en": "Enable WAF for the ALB instance by setting LoadBalancerEdition to 'StandardWithWaf'.",
		"zh": "通过将 LoadBalancerEdition 设置为 'StandardWithWaf' 为 ALB 实例开启 WAF 防护。",
	},
	"resource_types": ["ALIYUN::ALB::LoadBalancer"],
}

# Check if ALB has WAF enabled via its edition
is_waf_enabled(resource) if {
	helpers.get_property(resource, "LoadBalancerEdition", "") == "StandardWithWaf"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_waf_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LoadBalancerEdition"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
