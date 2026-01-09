package infraguard.rules.aliyun.actiontrail_trail_intact_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:actiontrail-trail-intact-enabled",
	"name": {
		"en": "ActionTrail Trail Intact Enabled",
		"zh": "开启操作审计全量日志跟踪",
	},
	"severity": "high",
	"description": {
		"en": "ActionTrail trail should be enabled and track all event types (Read and Write).",
		"zh": "操作审计中存在开启状态的跟踪，且跟踪全部地域和全部事件类型。",
	},
	"reason": {
		"en": "The ActionTrail trail is not enabled or does not track all event types.",
		"zh": "操作审计跟踪未开启或未跟踪所有事件类型。",
	},
	"recommendation": {
		"en": "Enable the trail using ALIYUN::ACTIONTRAIL::TrailLogging and set EventRW to All in ALIYUN::ACTIONTRAIL::Trail.",
		"zh": "使用 ALIYUN::ACTIONTRAIL::TrailLogging 启用跟踪，并在 ALIYUN::ACTIONTRAIL::Trail 中将 EventRW 设置为 All。",
	},
	"resource_types": ["ALIYUN::ACTIONTRAIL::Trail"],
}

# Get all enabled trail names from TrailLogging resources
enabled_trails := {name |
	some logging in helpers.resources_by_type("ALIYUN::ACTIONTRAIL::TrailLogging")
	helpers.get_property(logging, "Enable", false) == true
	name := helpers.get_property(logging, "Name", "")
	name != ""
}

# Check if a trail is enabled (referenced by an enabled TrailLogging)
is_trail_enabled(trail_name) if {
	trail_name in enabled_trails
}

# Check if trail tracks all events
is_track_all_events(resource) if {
	helpers.get_property(resource, "EventRW", "Write") == "All"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)

	# Get the trail name (either property Name or resource name if not set?)
	# Trail Name property is required.
	trail_name := helpers.get_property(resource, "Name", "")

	# Check conditions
	violation := check_violation(trail_name, resource)
	violation != null

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EventRW"], # Approximate path
		"meta": {
			"severity": rule_meta.severity,
			"reason": violation,
			"recommendation": rule_meta.recommendation,
		},
	}
}

check_violation(trail_name, resource) := reason if {
	not is_track_all_events(resource)
	reason := rule_meta.reason.zh # "Not tracking all events"
}

check_violation(trail_name, resource) := reason if {
	is_track_all_events(resource)
	not is_trail_enabled(trail_name)
	reason := "操作审计跟踪未开启 (缺少启用的 TrailLogging)"
}
