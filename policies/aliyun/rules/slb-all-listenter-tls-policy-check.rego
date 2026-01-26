package infraguard.rules.aliyun.slb_all_listenter_tls_policy_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-all-listenter-tls-policy-check",
	"name": {
		"en": "SLB Listener TLS Policy Check",
		"zh": "SLB 监听使用安全 TLS 策略"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures SLB HTTPS listeners use secure TLS cipher policies.",
		"zh": "确保 SLB HTTPS 监听使用安全的 TLS 加密策略。"
	},
	"reason": {
		"en": "Weak cipher suites can be exploited to decrypt intercepted traffic.",
		"zh": "弱加密套件可能被利用来解密截获的流量。"
	},
	"recommendation": {
		"en": "Use a recommended TLS policy like 'tls_cipher_policy_1_2'.",
		"zh": "使用推荐的 TLS 策略，如 'tls_cipher_policy_1_2'。"
	},
	"resource_types": ["ALIYUN::SLB::Listener"],
}

is_compliant(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol != "https"
}

is_compliant(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol == "https"
	policy := helpers.get_property(resource, "TLSCipherPolicy", "")

	# Example: must be 1.2 or higher
	policy != ""
	not helpers.includes(["tls_cipher_policy_1_0", "tls_cipher_policy_1_1"], policy)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TLSCipherPolicy"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
