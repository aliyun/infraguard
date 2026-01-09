package infraguard.rules.aliyun.redis_public_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:redis-public-and-any-ip-access-check",
	"name": {
		"en": "Redis Public and Any IP Access Check",
		"zh": "Redis 实例不开启公网或安全白名单不设置为允许任意来源访问",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that Redis instances do not have public access enabled or an open whitelist.",
		"zh": "确保 Redis 实例未开启公网访问，或者白名单未设置为对所有 IP 开放。",
	},
	"reason": {
		"en": "Public access to Redis is a severe security risk, as it is often targets for brute force attacks and data theft.",
		"zh": "Redis 的公网访问是一个严重的安全风险，因为它经常成为暴力破解攻击和数据窃取的方目标。",
	},
	"recommendation": {
		"en": "Disable public connection for the Redis instance and restrict access via IP whitelists.",
		"zh": "禁用 Redis 实例的公网连接，并通过 IP 白名单限制访问。",
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	# Check Connections property
	connections := helpers.get_property(resource, "Connections", {})

	# It is compliant if PublicConnection is NOT present
	object.get(connections, "PublicConnection", null) == null
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Connections", "PublicConnection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
