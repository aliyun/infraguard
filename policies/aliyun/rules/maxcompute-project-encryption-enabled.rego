package infraguard.rules.aliyun.maxcompute_project_encryption_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "maxcompute-project-encryption-enabled",
	"name": {
		"en": "MaxCompute Project Encryption Enabled",
		"zh": "MaxCompute 项目开启加密"
	},
	"severity": "high",
	"description": {
		"en": "Ensures MaxCompute projects have encryption enabled to protect stored data.",
		"zh": "确保 MaxCompute 项目启用了加密以保护存储的数据。"
	},
	"reason": {
		"en": "Encryption protects sensitive data stored in MaxCompute projects from unauthorized access.",
		"zh": "加密可以保护 MaxCompute 项目中存储的敏感数据免受非授权访问。"
	},
	"recommendation": {
		"en": "Enable encryption for the MaxCompute project.",
		"zh": "为 MaxCompute 项目启用加密。"
	},
	"resource_types": ["ALIYUN::MaxCompute::Project"],
}

# Check if encryption is enabled
is_compliant(resource) if {
	# Direct access to nested properties
	props := resource.Properties.Properties
	props != null
	encryption := props.Encryption
	encryption != null
	encryption.Enable == true
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MaxCompute::Project")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Encryption", "Enable"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
