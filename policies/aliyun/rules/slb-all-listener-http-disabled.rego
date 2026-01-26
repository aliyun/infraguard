package infraguard.rules.aliyun.slb_all_listener_http_disabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-all-listener-http-disabled",
	"name": {
		"en": "SLB All Listeners HTTP Disabled",
		"zh": "SLB 禁用 HTTP 监听"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures no SLB listeners use the insecure HTTP protocol.",
		"zh": "确保没有 SLB 监听使用不安全的 HTTP 协议。"
	},
	"reason": {
		"en": "HTTP traffic is unencrypted and vulnerable to interception.",
		"zh": "HTTP 流量未加密，容易被截获。"
	},
	"recommendation": {
		"en": "Disable HTTP listeners and use HTTPS instead.",
		"zh": "禁用 HTTP 监听并改用 HTTPS。"
	},
	"resource_types": ["ALIYUN::SLB::Listener"],
}

is_compliant(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol != "http"
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
