package infraguard.rules.aliyun.nas_filesystem_encrypt_type_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "nas-filesystem-encrypt-type-check",
	"name": {
		"en": "NAS file system encryption configured",
		"zh": "NAS 文件系统设置了加密",
	},
	"description": {
		"en": "NAS file system has encryption configured, considered compliant.",
		"zh": "NAS 文件系统设置了加密,视为合规。",
	},
	"severity": "low",
	"resource_types": ["ALIYUN::NAS::FileSystem"],
	"reason": {
		"en": "NAS file system does not have encryption configured",
		"zh": "NAS 文件系统未设置加密",
	},
	"recommendation": {
		"en": "Configure encryption for NAS file system to protect data at rest using KMS keys",
		"zh": "为 NAS 文件系统配置加密以使用 KMS 密钥保护静态数据",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::NAS::FileSystem")

	# Check if EncryptType is set to 1 (encrypted)
	encrypt_type := helpers.get_property(resource, "EncryptType", 0)
	encrypt_type != 1

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
