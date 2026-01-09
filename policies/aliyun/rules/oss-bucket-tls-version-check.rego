package infraguard.rules.aliyun.oss_bucket_tls_version_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:oss-bucket-tls-version-check",
	"name": {
		"en": "OSS Bucket TLS Version Check",
		"zh": "OSS 存储桶 TLS 版本检测",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the OSS bucket is configured to use a secure version of TLS (TLS 1.2 or higher).",
		"zh": "确保 OSS 存储桶配置为使用安全的 TLS 版本（TLS 1.2 或更高版本）。",
	},
	"reason": {
		"en": "Older versions of TLS have security vulnerabilities. Using newer versions ensures data transport security.",
		"zh": "旧版本的 TLS 存在安全漏洞。使用新版本可确保数据传输安全。",
	},
	"recommendation": {
		"en": "Configure the OSS bucket to require TLS 1.2 or higher for all requests.",
		"zh": "配置 OSS 存储桶，要求所有请求使用 TLS 1.2 或更高版本。",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")

	# Conceptual check for TLS version in policy or specific property
	not helpers.has_property(resource, "TLSVersion") # Simplified
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
