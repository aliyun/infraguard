package infraguard.rules.aliyun.slb_listener_https_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:slb-listener-https-enabled",
	"name": {
		"en": "SLB Listener HTTPS Enabled",
		"zh": "SLB 监听开启 HTTPS"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures SLB listeners use HTTPS protocol for secure communication.",
		"zh": "确保 SLB 监听使用 HTTPS 协议以保障通信安全。"
	},
	"reason": {
		"en": "HTTP protocol is insecure and prone to eavesdropping. HTTPS provides encryption.",
		"zh": "HTTP 协议不安全，容易被窃听。HTTPS 提供加密保障。"
	},
	"recommendation": {
		"en": "Configure SLB listeners to use HTTPS instead of HTTP.",
		"zh": "将 SLB 监听配置为使用 HTTPS 而非 HTTP。"
	},
	"resource_types": ["ALIYUN::SLB::Listener"],
}

is_compliant(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol == "https"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Protocol"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
