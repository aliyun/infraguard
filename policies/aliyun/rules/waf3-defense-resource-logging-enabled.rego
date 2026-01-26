package infraguard.rules.aliyun.waf3_defense_resource_logging_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "waf3-defense-resource-logging-enabled",
	"name": {
		"en": "WAF 3.0 Logging Enabled",
		"zh": "WAF 3.0 防护资源开启日志审计"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that logging is enabled for resources protected by WAF 3.0.",
		"zh": "确保 WAF 3.0 防护的资源已开启日志审计。"
	},
	"reason": {
		"en": "Logging is critical for tracking web attacks and security incidents.",
		"zh": "日志记录对于追踪网络攻击和安全事件至关重要。"
	},
	"recommendation": {
		"en": "Enable log service for the WAF 3.0 instance.",
		"zh": "为 WAF 3.0 实例开启日志服务。"
	},
	"resource_types": ["ALIYUN::WAF3::Instance"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "LogService", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::WAF3::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LogService"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
