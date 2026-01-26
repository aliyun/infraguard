package infraguard.rules.aliyun.slb_instance_log_enabled

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "slb-instance-log-enabled",
	"name": {
		"en": "SLB Instance Logging Enabled",
		"zh": "SLB 实例开启访问日志",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that access logging is enabled for the SLB instance.",
		"zh": "确保 SLB 实例开启了访问日志。",
	},
	"reason": {
		"en": "Access logs are essential for auditing traffic and troubleshooting connectivity and security issues.",
		"zh": "访问日志对于审计流量以及排查连接和安全问题至关重要。",
	},
	"recommendation": {
		"en": "Enable access logging for the SLB instance.",
		"zh": "为 SLB 实例开启访问日志。",
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")

	# Conceptual check for logging
	not helpers.has_property(resource, "AccessLog")
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
