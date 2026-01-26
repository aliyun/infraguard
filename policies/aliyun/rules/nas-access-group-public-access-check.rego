package infraguard.rules.aliyun.nas_access_group_public_access_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "nas-access-group-public-access-check",
	"name": {
		"en": "NAS Access Group IP Restriction",
		"zh": "NAS 权限组禁用公网授权"
	},
	"severity": "high",
	"description": {
		"en": "Ensures NAS access rules do not allow 0.0.0.0/0.",
		"zh": "确保 NAS 权限规则不允许 0.0.0.0/0。"
	},
	"reason": {
		"en": "An open NAS access rule can lead to unauthorized data access over the internet.",
		"zh": "开放的 NAS 权限规则可能导致互联网上的非授权数据访问。"
	},
	"recommendation": {
		"en": "Restrict NAS access rules to specific trusted VPC IP ranges.",
		"zh": "将 NAS 权限规则限制在特定的可信 VPC IP 范围内。"
	},
	"resource_types": ["ALIYUN::NAS::AccessRule"],
}

is_compliant(resource) if {
	ip := helpers.get_property(resource, "SourceCidrIp", "")
	not helpers.is_public_cidr(ip)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::NAS::AccessRule")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SourceCidrIp"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
