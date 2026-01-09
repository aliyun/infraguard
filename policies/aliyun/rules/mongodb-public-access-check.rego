package infraguard.rules.aliyun.mongodb_public_access_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:mongodb-public-access-check",
	"name": {
		"en": "MongoDB Whitelist Internet Restriction",
		"zh": "MongoDB 白名单禁用公网开放"
	},
	"severity": "high",
	"description": {
		"en": "Ensures MongoDB security IP whitelists do not contain 0.0.0.0/0.",
		"zh": "确保 MongoDB 安全 IP 白名单中不包含 0.0.0.0/0。"
	},
	"reason": {
		"en": "An open MongoDB whitelist allows unrestricted access to sensitive data over the internet.",
		"zh": "开放的 MongoDB 白名单允许通过互联网无限制地访问敏感数据。"
	},
	"recommendation": {
		"en": "Restrict the MongoDB whitelist to trusted IP ranges.",
		"zh": "将 MongoDB 白名单限制在可信 IP 范围内。"
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

is_compliant(resource) if {
	whitelist_str := helpers.get_property(resource, "SecurityIPArray", "")
	whitelist := split(whitelist_str, ",")
	not has_public_ip(whitelist)
}

has_public_ip(whitelist) if {
	some ip in whitelist
	helpers.is_public_cidr(trim_space(ip))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MONGODB::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIPArray"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
