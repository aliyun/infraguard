package infraguard.rules.aliyun.oss_bucket_server_side_encryption_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "oss-bucket-server-side-encryption-enabled",
	"name": {
		"en": "OSS Bucket Server-Side Encryption Enabled",
		"zh": "OSS 存储空间开启服务端加密",
	},
	"severity": "high",
	"description": {
		"en": "OSS buckets should have server-side encryption enabled to protect data at rest. Server-side encryption uses KMS or AES256 to encrypt data stored in OSS.",
		"zh": "OSS 存储空间应开启服务端加密以保护静态数据。服务端加密使用 KMS 或 AES256 对存储在 OSS 中的数据进行加密。",
	},
	"reason": {
		"en": "The OSS bucket does not have server-side encryption enabled, which may expose sensitive data to unauthorized access.",
		"zh": "OSS 存储空间未开启服务端加密，可能导致敏感数据暴露给未授权访问。",
	},
	"recommendation": {
		"en": "Enable server-side encryption for the OSS bucket by configuring the ServerSideEncryptionConfiguration property with SSEAlgorithm set to KMS, AES256, or SM4.",
		"zh": "通过配置 ServerSideEncryptionConfiguration 属性并将 SSEAlgorithm 设置为 KMS、AES256 或 SM4，为 OSS 存储空间启用服务端加密。",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	not has_server_side_encryption(resource)
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

has_server_side_encryption(resource) if {
	helpers.has_property(resource, "ServerSideEncryptionConfiguration")
	sse_config := resource.Properties.ServerSideEncryptionConfiguration
	sse_config.SSEAlgorithm in ["KMS", "AES256", "SM4"]
}
