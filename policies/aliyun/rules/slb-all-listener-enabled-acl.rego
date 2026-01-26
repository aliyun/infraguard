package infraguard.rules.aliyun.slb_all_listener_enabled_acl

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-all-listener-enabled-acl",
	"name": {
		"en": "SLB All Listeners Have Access Control",
		"zh": "SLB 实例所有运行中的监听都设置访问控制"
	},
	"severity": "medium",
	"description": {
		"en": "All running listeners of SLB instances should have access control lists (ACL) configured for security.",
		"zh": "SLB 实例所有运行中的监听都设置了访问控制，视为合规。"
	},
	"reason": {
		"en": "Listeners without ACL may allow unrestricted access, increasing security risks.",
		"zh": "未设置访问控制的监听可能允许无限制的访问，增加安全风险。"
	},
	"recommendation": {
		"en": "Configure ACL for all running listeners on SLB instances.",
		"zh": "为 SLB 实例的所有运行中监听配置访问控制列表。"
	},
	"resource_types": ["ALIYUN::SLB::Listener"],
}

is_compliant(resource) if {
	acl_status := helpers.get_property(resource, "AclStatus", "off")
	acl_status == "on"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AclStatus"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
