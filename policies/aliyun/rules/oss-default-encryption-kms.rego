package infraguard.rules.aliyun.oss_default_encryption_kms

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:oss-default-encryption-kms",
	"name": {
		"en": "OSS bucket server-side KMS encryption enabled",
		"zh": "OSS 存储空间开启服务端 KMS 加密",
	},
	"description": {
		"en": "OSS bucket has server-side KMS encryption enabled, considered compliant.",
		"zh": "OSS 存储空间开启服务端 KMS 加密,视为合规。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::OSS::Bucket"],
	"reason": {
		"en": "OSS bucket does not have server-side KMS encryption enabled",
		"zh": "OSS 存储空间未开启服务端 KMS 加密",
	},
	"recommendation": {
		"en": "Enable server-side KMS encryption for OSS bucket to protect data at rest",
		"zh": "为 OSS 存储空间开启服务端 KMS 加密以保护静态数据",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")

	# Check if ServerSideEncryptionConfiguration is set with KMS
	sse_config := helpers.get_property(resource, "ServerSideEncryptionConfiguration", {})
	sse_algorithm := object.get(sse_config, "SSEAlgorithm", "")

	sse_algorithm != "KMS"

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
