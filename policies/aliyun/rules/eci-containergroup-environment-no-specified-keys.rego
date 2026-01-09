package infraguard.rules.aliyun.eci_containergroup_environment_no_specified_keys

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:eci-containergroup-environment-no-specified-keys",
	"name": {
		"en": "ECI Container Group Does Not Contain Sensitive Environment Variables",
		"zh": "ECI 容器组不包含敏感环境变量",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that ECI container groups do not have sensitive environment variables like passwords or access keys.",
		"zh": "ECI 容器组不包含敏感环境变量（如密码、AccessKey 等），视为合规。",
	},
	"reason": {
		"en": "ECI container group contains sensitive environment variables, which may leak credentials.",
		"zh": "ECI 容器组包含敏感环境变量，可能导致凭证泄露。",
	},
	"recommendation": {
		"en": "Use Secrets or parameter store to manage sensitive environment variables.",
		"zh": "请使用 Secret 或参数存储来管理敏感环境变量。",
	},
	"resource_types": ["ALIYUN::ECI::ContainerGroup"],
}

# Default sensitive environment variable keys
default sensitive_keys := [
	"password",
	"passwd",
	"pwd",
	"secret",
	"key",
	"token",
	"credential",
	"access_key",
	"accesskey",
	"secret_key",
	"secretkey",
	"access_key_id",
]

# Get sensitive keys from parameters or use default
get_sensitive_keys := input.rule_parameters.sensitive_env_keys if {
	count(input.rule_parameters.sensitive_env_keys) > 0
} else := sensitive_keys

# Check if a key is sensitive (supports partial match)
is_sensitive_key(key) if {
	some sensitive in get_sensitive_keys
	contains(lower(key), lower(sensitive))
}

# Check if environment variable contains sensitive key
has_sensitive_env(container) if {
	some env in container.EnvironmentVar
	is_sensitive_key(env.Key)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECI::ContainerGroup")

	some container in resource.Properties.Container
	has_sensitive_env(container)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Container", "EnvironmentVar"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
