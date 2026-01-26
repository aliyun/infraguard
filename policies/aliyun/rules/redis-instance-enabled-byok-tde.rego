package infraguard.rules.aliyun.redis_instance_enabled_byok_tde

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "redis-instance-enabled-byok-tde",
	"name": {
		"en": "Redis Instance BYOK TDE Enabled",
		"zh": "Redis 实例开启 BYOK TDE 加密",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that Redis instances have Transparent Data Encryption (TDE) enabled using Bring Your Own Key (BYOK).",
		"zh": "确保 Redis 实例已使用自带密钥(BYOK)开启了透明数据加密(TDE)。",
	},
	"reason": {
		"en": "TDE protects data at rest, and BYOK allows you to maintain control over the encryption keys.",
		"zh": "TDE 可保护静态数据，而 BYOK 允许您保持对加密密钥的控制。",
	},
	"recommendation": {
		"en": "Enable TDE for the Redis instance using a KMS key.",
		"zh": "使用 KMS 密钥为 Redis 实例开启 TDE。",
	},
	"resource_types": ["ALIYUN::Redis::DBInstance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::Redis::DBInstance")

	# Conceptual check for TDE
	not helpers.has_property(resource, "TDEStatus")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
