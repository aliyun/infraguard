package infraguard.rules.aliyun.redis_instance_enabled_ssl

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:redis-instance-enabled-ssl",
	"name": {
		"en": "Redis Instance SSL Enabled",
		"zh": "Redis 实例开启 SSL 加密"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Redis instances have SSL encryption enabled.",
		"zh": "确保 Redis 实例开启了 SSL 加密。"
	},
	"reason": {
		"en": "SSL encryption protects Redis data in transit from being intercepted.",
		"zh": "SSL 加密保护传输中的 Redis 数据不被截获。"
	},
	"recommendation": {
		"en": "Enable SSL for the Redis instance.",
		"zh": "为 Redis 实例开启 SSL 加密。"
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	ssl := helpers.get_property(resource, "SSLEnabled", "Disable")
	ssl == "Enable"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SSLEnabled"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
