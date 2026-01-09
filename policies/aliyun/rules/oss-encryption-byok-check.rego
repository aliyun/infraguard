package infraguard.rules.aliyun.oss_encryption_byok_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:oss-encryption-byok-check",
	"name": {
		"en": "OSS Bucket BYOK Encryption Check",
		"zh": "OSS 存储空间使用自定义 KMS 密钥加密",
	},
	"severity": "medium",
	"description": {
		"en": "OSS buckets should use customer-managed KMS keys (BYOK - Bring Your Own Key) for encryption. This provides better control over encryption keys and meets compliance requirements.",
		"zh": "OSS 存储空间应使用客户管理的 KMS 密钥（BYOK - 自带密钥）进行加密。这提供了对加密密钥的更好控制并满足合规要求。",
	},
	"reason": {
		"en": "The OSS bucket does not use customer-managed KMS keys for encryption, which may not meet compliance requirements for key management.",
		"zh": "OSS 存储空间未使用客户管理的 KMS 密钥进行加密，可能无法满足密钥管理的合规要求。",
	},
	"recommendation": {
		"en": "Configure the OSS bucket to use customer-managed KMS keys by setting SSEAlgorithm to KMS and specifying a KMSMasterKeyID in ServerSideEncryptionConfiguration.",
		"zh": "通过将 SSEAlgorithm 设置为 KMS 并在 ServerSideEncryptionConfiguration 中指定 KMSMasterKeyID，将 OSS 存储空间配置为使用客户管理的 KMS 密钥。",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	not uses_byok_encryption(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ServerSideEncryptionConfiguration"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

uses_byok_encryption(resource) if {
	helpers.has_property(resource, "ServerSideEncryptionConfiguration")
	sse_config := resource.Properties.ServerSideEncryptionConfiguration
	sse_config.SSEAlgorithm == "KMS"
	sse_config.KMSMasterKeyID != null
}
