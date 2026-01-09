package infraguard.rules.aliyun.redis_instance_tls_version_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:redis-instance-tls-version-check",
	"name": {
		"en": "Redis Instance TLS Version Check",
		"zh": "Redis 实例开启 SSL 并使用指定的 TLS 版本"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Redis instance has SSL enabled with acceptable TLS version.",
		"zh": "确保 Redis 实例开启 SSL 且使用的 TLS 版本在可接受范围内。"
	},
	"reason": {
		"en": "Using strong TLS versions ensures secure communication.",
		"zh": "使用强 TLS 版本确保通信安全。"
	},
	"recommendation": {
		"en": "Enable SSL with recommended TLS version for Redis instance.",
		"zh": "为 Redis 实例启用 SSL 并使用推荐的 TLS 版本。"
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	ssl_enabled := helpers.get_property(resource, "SSLEnabled", "Disable")
	ssl_enabled == "Enable"
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
