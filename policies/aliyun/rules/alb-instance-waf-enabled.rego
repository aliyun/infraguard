package infraguard.rules.aliyun.alb_instance_waf_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:alb-instance-waf-enabled",
	"name": {
		"en": "ALB Instance Has WAF Protection",
		"zh": "ALB 实例开启 WEB 应用防火墙防护",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that ALB instances have WAF3 (Web Application Firewall) protection enabled.",
		"zh": "确保 ALB 实例已启用 WAF3（Web 应用防火墙）防护。",
	},
	"reason": {
		"en": "WAF protection helps protect against common web vulnerabilities and attacks.",
		"zh": "WAF 防护有助于防范常见的 Web 漏洞和攻击。",
	},
	"recommendation": {
		"en": "Enable WAF3 protection for the ALB instance.",
		"zh": "为 ALB 实例启用 WAF3 防护。",
	},
	"resource_types": ["ALIYUN::ALB::LoadBalancer"],
}

# Check if WAF protection is enabled via LoadBalancerEdition
is_compliant(resource) if {
	edition := helpers.get_property(resource, "LoadBalancerEdition", "")
	edition == "StandardWithWaf"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "WafEnabled"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
