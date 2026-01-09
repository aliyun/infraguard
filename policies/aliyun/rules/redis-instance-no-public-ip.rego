package infraguard.rules.aliyun.redis_instance_no_public_ip

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:redis-instance-no-public-ip",
	"name": {
		"en": "Redis Instance No Public IP",
		"zh": "Redis 实例未设置公网 IP"
	},
	"severity": "high",
	"description": {
		"en": "Ensures Redis instance does not have public IP assigned.",
		"zh": "确保 Redis 实例未设置公网 IP。"
	},
	"reason": {
		"en": "Public IP exposes Redis instance to internet attacks.",
		"zh": "公网 IP 使 Redis 实例暴露于互联网攻击。"
	},
	"recommendation": {
		"en": "Remove public IP from the Redis instance.",
		"zh": "移除 Redis 实例的公网 IP。"
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	connections := helpers.get_property(resource, "Connections", {})
	object.get(connections, "PublicConnection", null) == null
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Connections", "PublicConnection"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
