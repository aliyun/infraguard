package infraguard.rules.aliyun.slb_all_listener_health_check_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-all-listener-health-check-enabled",
	"name": {
		"en": "SLB All Listeners Health Check Enabled",
		"zh": "SLB 所有监听开启健康检查"
	},
	"severity": "high",
	"description": {
		"en": "Ensures all SLB listeners have health checks enabled.",
		"zh": "确保所有 SLB 监听均开启了健康检查。"
	},
	"reason": {
		"en": "Health checks ensure that traffic is only sent to healthy backend instances.",
		"zh": "健康检查确保流量仅发送到健康的后端实例。"
	},
	"recommendation": {
		"en": "Enable health checks for all SLB listeners.",
		"zh": "为所有 SLB 监听开启健康检查。"
	},
	"resource_types": ["ALIYUN::SLB::Listener"],
}

is_compliant(resource) if {
	# HealthCheck is a map with Switch property
	hc := helpers.get_property(resource, "HealthCheck", {})
	switch_val := object.get(hc, "Switch", "off")
	switch_val == "on"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "HealthCheck"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
