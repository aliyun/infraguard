package infraguard.rules.aliyun.mongodb_public_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mongodb-public-and-any-ip-access-check",
	"name": {
		"en": "MongoDB Public and Any IP Access Check",
		"zh": "MongoDB 实例不开启公网或安全白名单不设置为允许任意来源访问",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that MongoDB instances do not have an open whitelist (0.0.0.0/0).",
		"zh": "确保 MongoDB 实例未设置开放白名单（0.0.0.0/0）。",
	},
	"reason": {
		"en": "Setting the whitelist to 0.0.0.0/0 allows any IP to attempt connection, significantly increasing the risk of data breaches or brute force attacks.",
		"zh": "将白名单设置为 0.0.0.0/0 允许任何 IP 尝试连接，大大增加了数据泄露或暴力破解的风险。",
	},
	"recommendation": {
		"en": "Restrict the IP whitelist for the MongoDB instance to specific trusted IP ranges.",
		"zh": "将 MongoDB 实例的 IP 白名单限制为特定的可信 IP 范围。",
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

is_compliant(resource) if {
	# Check SecurityIPArray property (string)
	whitelist_str := helpers.get_property(resource, "SecurityIPArray", "")
	whitelist := split(whitelist_str, ",")
	not has_open_cidr(whitelist)
}

has_open_cidr(whitelist) if {
	some cidr in whitelist
	helpers.is_public_cidr(trim_space(cidr))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MONGODB::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIPArray"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
