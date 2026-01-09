package infraguard.rules.aliyun.ecs_snapshot_policy_timepoints_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ecs-snapshot-policy-timepoints-check",
	"name": {
		"en": "ECS auto snapshot policy timepoints configured reasonably",
		"zh": "为自动快照策略设置合理的创建时间点",
	},
	"description": {
		"en": "The snapshot creation timepoints in the auto snapshot policy are within the specified time range, considered compliant. Creating snapshots temporarily reduces block storage I/O performance, with performance differences generally within 10%, causing brief slowdowns. It is recommended to select timepoints that avoid business peak hours.",
		"zh": "自动快照策略中设置的快照创建时间点在参数指定的时间点范围内,视为合规。创建快照会暂时降低块存储 I/O 性能,一般性能差异在 10%以内,出现短暂瞬间变慢。建议您选择避开业务高峰的时间点。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::AutoSnapshotPolicy"],
	"reason": {
		"en": "Auto snapshot policy timepoints may not be configured to avoid business peak hours",
		"zh": "自动快照策略时间点可能未配置为避开业务高峰时段",
	},
	"recommendation": {
		"en": "Configure snapshot creation timepoints during off-peak hours (e.g., 2:00-6:00 AM) to minimize impact on business operations",
		"zh": "将快照创建时间点配置在非高峰时段(如凌晨 2:00-6:00)以最小化对业务运营的影响",
	},
}

# Recommended off-peak hours: 2:00-6:00 AM (hours 2-5)
recommended_timepoints := {2, 3, 4, 5}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::AutoSnapshotPolicy")

	# Get configured timepoints
	timepoints := helpers.get_property(resource, "TimePoints", [])

	# Check if any timepoint is outside recommended range
	some point in timepoints
	not point in recommended_timepoints

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TimePoints"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
