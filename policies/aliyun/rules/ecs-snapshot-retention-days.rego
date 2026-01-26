package infraguard.rules.aliyun.ecs_snapshot_retention_days

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-snapshot-retention-days",
	"name": {
		"en": "ECS auto snapshot retention days meets requirements",
		"zh": "ECS 自动快照保留天数满足指定要求",
	},
	"description": {
		"en": "ECS auto snapshot policy retention days is greater than the specified number of days, considered compliant. Default value: 7 days.",
		"zh": "ECS 自动快照策略设置快照保留天数大于设置的天数,视为合规。默认值:7 天。",
	},
	"severity": "low",
	"resource_types": ["ALIYUN::ECS::AutoSnapshotPolicy"],
	"reason": {
		"en": "Auto snapshot retention days is less than the minimum required days (7 days)",
		"zh": "自动快照保留天数少于最低要求天数(7 天)",
	},
	"recommendation": {
		"en": "Set auto snapshot retention days to at least 7 days to ensure adequate backup coverage",
		"zh": "将自动快照保留天数设置为至少 7 天以确保足够的备份覆盖",
	},
}

# Minimum retention days requirement
min_retention_days := 7

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::AutoSnapshotPolicy")

	# Get retention days (-1 means permanent, which is compliant)
	retention_days := helpers.get_property(resource, "RetentionDays", 0)

	# Check if retention is less than minimum (but not -1 for permanent)
	retention_days != -1
	retention_days < min_retention_days

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RetentionDays"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
