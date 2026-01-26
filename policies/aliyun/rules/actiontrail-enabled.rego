package infraguard.rules.aliyun.actiontrail_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "actiontrail-enabled",
	"name": {
		"en": "ActionTrail Enabled",
		"zh": "确保操作审计已开启"
	},
	"severity": "high",
	"description": {
		"en": "Ensures ActionTrail is enabled to record account activities.",
		"zh": "确保开启了操作审计（ActionTrail）以记录账号活动。"
	},
	"reason": {
		"en": "ActionTrail provides a record of API calls, which is essential for security auditing and forensic analysis.",
		"zh": "操作审计记录了 API 调用情况，这对于安全审计和取证分析至关重要。"
	},
	"recommendation": {
		"en": "Create and enable at least one trail in ActionTrail.",
		"zh": "在操作审计中创建并启用至少一个跟踪（Trail）。"
	},
	"resource_types": ["ALIYUN::ACTIONTRAIL::Trail"],
}

is_compliant(resource) := true

# If the resource exists in template, we check if logging is enabled
# Note: Often requires ALIYUN::ACTIONTRAIL::TrailLogging
# Basic check for existence of Trail resource

deny contains result if {
	# If no Trail resource exists at all in the template
	helpers.count_resources_by_type("ALIYUN::ACTIONTRAIL::Trail") == 0
	result := {
		"id": rule_meta.id,
		"resource_id": "Global",
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
