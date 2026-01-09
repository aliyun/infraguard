package infraguard.rules.aliyun.slb_all_listener_http_redirect_https

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:slb-all-listener-http-redirect-https",
	"name": {
		"en": "SLB HTTP Redirect to HTTPS Enabled",
		"zh": "SLB 监听强制跳转 HTTPS"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures SLB HTTP listeners are configured to redirect traffic to HTTPS.",
		"zh": "确保 SLB HTTP 监听已配置为将流量重定向至 HTTPS。"
	},
	"reason": {
		"en": "Redirecting HTTP to HTTPS ensures all client communication is encrypted.",
		"zh": "将 HTTP 重定向至 HTTPS 确保了所有客户端通信均经过加密。"
	},
	"recommendation": {
		"en": "Enable HTTP-to-HTTPS redirection for the SLB listener.",
		"zh": "为 SLB 监听开启 HTTP 转 HTTPS 重定向。"
	},
	"resource_types": ["ALIYUN::SLB::Listener"],
}

is_compliant(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol != "http"
}

is_compliant(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol == "http"

	# In ROS, check for HttpConfig.ListenerForward
	http_config := helpers.get_property(resource, "HttpConfig", {})
	is_object(http_config)
	http_config.ListenerForward == "on"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "HttpConfig", "ListenerForward"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
