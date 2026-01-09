package infraguard.rules.aliyun.alb_all_listener_health_check_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:alb-all-listener-health-check-enabled",
	"name": {
		"en": "ALB All Listeners Health Check Enabled",
		"zh": "ALB 所有监听开启健康检查"
	},
	"severity": "high",
	"description": {
		"en": "Ensures all ALB listeners have health checks enabled.",
		"zh": "确保所有 ALB 监听均开启了健康检查。"
	},
	"reason": {
		"en": "Health checks are vital for detecting and bypassing unhealthy backend servers.",
		"zh": "健康检查对于发现和避开不健康的后端服务器至关重要。"
	},
	"recommendation": {
		"en": "Enable health checks for all ALB listeners.",
		"zh": "为所有 ALB 监听开启健康检查。"
	},
	"resource_types": ["ALIYUN::ALB::Listener"],
}

# Resolve ServerGroupId from Ref or string
resolve_server_group_id(val) := id if {
	is_object(val)
	id := val.Ref
} else := val if {
	is_string(val)
}

# Check if listener's server groups have health check enabled
is_compliant(resource) if {
	default_actions := helpers.get_property(resource, "DefaultActions", [])
	some action in default_actions
	action.Type == "ForwardGroup"
	forward_group_config := action.ForwardGroupConfig
	some tuple in forward_group_config.ServerGroupTuples
	server_group_id_val := tuple.ServerGroupId
	server_group_id := resolve_server_group_id(server_group_id_val)

	# Find the server group resource
	some name, server_group in input.Resources
	name == server_group_id
	server_group.Type == "ALIYUN::ALB::ServerGroup"

	# Check health check config
	hc := helpers.get_property(server_group, "HealthCheckConfig", {})
	helpers.is_true(object.get(hc, "HealthCheckEnabled", true))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "HealthCheckConfig", "HealthCheckEnabled"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
