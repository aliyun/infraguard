package infraguard.rules.aliyun.waf_instance_logging_enabled

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:waf-instance-logging-enabled",
	"name": {
		"en": "WAF Instance Logging Enabled",
		"zh": "WAF 实例开启日志",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that logging is enabled for the WAF instance for auditing and security analysis.",
		"zh": "确保 WAF 实例开启了日志，以便进行审计和安全分析。",
	},
	"reason": {
		"en": "WAF logs provide critical information about web attacks and traffic patterns.",
		"zh": "WAF 日志提供了关于 Web 攻击和流量模式的关键信息。",
	},
	"recommendation": {
		"en": "Enable logging for the WAF instance.",
		"zh": "为 WAF 实例开启日志。",
	},
	"resource_types": ["ALIYUN::WAF::Instance", "ALIYUN::WAF3::Instance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::WAF::Instance", "ALIYUN::WAF3::Instance"])

	# Conceptual check for logging
	not helpers.has_property(resource, "LogConfig")
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
