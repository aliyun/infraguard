package infraguard.rules.aliyun.slb_backendserver_weight_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-backendserver-weight-check",
	"name": {
		"en": "SLB Backend Server Weight Check",
		"zh": "SLB 后端服务器权重配置核查"
	},
	"severity": "low",
	"description": {
		"en": "Ensures SLB backend servers have reasonable weight configurations.",
		"zh": "确保 SLB 后端服务器具有合理的权重配置。"
	},
	"reason": {
		"en": "Uneven weight distribution can lead to unbalanced traffic and potential overload.",
		"zh": "权重分配不均可能导致流量失衡和潜在的负载过载。"
	},
	"recommendation": {
		"en": "Ensure backend server weights are set correctly.",
		"zh": "确保后端服务器权重设置正确。"
	},
	"resource_types": ["ALIYUN::SLB::BackendServerAttachment"],
}

is_compliant(resource) if {
	servers := helpers.get_property(resource, "BackendServers", [])
	some server in servers
	weight := object.get(server, "Weight", 100)
	weight > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::BackendServerAttachment")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "BackendServers"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
