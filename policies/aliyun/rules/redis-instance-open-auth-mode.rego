package infraguard.rules.aliyun.redis_instance_open_auth_mode

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:redis-instance-open-auth-mode",
	"name": {
		"en": "Redis Authentication Mode Enabled",
		"zh": "Redis 强制开启认证模式"
	},
	"severity": "high",
	"description": {
		"en": "Ensures Redis instances require authentication and are not in 'no-password' mode.",
		"zh": "确保 Redis 实例需要身份验证，且不处于'免密'模式。"
	},
	"reason": {
		"en": "Disabling authentication allows anyone with network access to read or modify your Redis data.",
		"zh": "禁用身份验证会允许任何拥有网络访问权限的人读取或修改您的 Redis 数据。"
	},
	"recommendation": {
		"en": "Enable password authentication for the Redis instance.",
		"zh": "为 Redis 实例启用密码身份验证。"
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	# In ROS, password free mode is controlled by VpcPasswordFree
	helpers.is_false(helpers.get_property(resource, "VpcPasswordFree", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcPasswordFree"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
