package infraguard.rules.aliyun.sls_logstore_hot_ttl_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "sls-logstore-hot-ttl-check",
	"name": {
		"en": "SLS Logstore Smart Tier Storage Enabled",
		"zh": "SLS 日志库开启智能冷热分层存储"
	},
	"severity": "low",
	"description": {
		"en": "Ensures SLS Logstores have intelligent hot/cold tier storage enabled for cost optimization.",
		"zh": "确保 SLS 日志库开启了智能冷热分层存储功能以优化成本。"
	},
	"reason": {
		"en": "Hot/cold tier storage helps optimize costs by automatically moving less frequently accessed data to cheaper storage.",
		"zh": "智能冷热分层存储通过将访问频率较低的数据自动移动到更便宜的存储层来帮助优化成本。"
	},
	"recommendation": {
		"en": "Enable intelligent hot/cold tier storage for the Logstore.",
		"zh": "为日志库启用智能冷热分层存储功能。"
	},
	"resource_types": ["ALIYUN::SLS::Logstore"],
}

is_compliant(resource) if {
	# Check TTL - hot storage enabled when TTL > 7 days
	# Standard tier with TTL > 7 days indicates hot storage is available
	ttl := helpers.get_property(resource, "TTL", 0)
	ttl > 7

	# Check that PreserveStorage is not true (if true, TTL is ignored)
	preserve := helpers.get_property(resource, "PreserveStorage", false)
	preserve != true
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLS::Logstore")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TTL"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
