package infraguard.rules.aliyun.oss_bucket_logging_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "oss-bucket-logging-enabled",
	"name": {
		"en": "OSS Bucket Logging Enabled",
		"zh": "OSS 存储空间开启日志转存",
	},
	"severity": "medium",
	"description": {
		"en": "OSS buckets should have logging enabled to track access and operations. Logging helps with security auditing, troubleshooting, and compliance requirements.",
		"zh": "OSS 存储空间应开启日志转存以跟踪访问和操作。日志记录有助于安全审计、故障排查和合规要求。",
	},
	"reason": {
		"en": "The OSS bucket does not have logging enabled, which makes it difficult to track access and operations for security and compliance purposes.",
		"zh": "OSS 存储空间未开启日志转存，难以跟踪访问和操作以满足安全和合规要求。",
	},
	"recommendation": {
		"en": "Enable logging for the OSS bucket by configuring the LoggingConfiguration property with TargetBucket and optionally TargetPrefix.",
		"zh": "通过配置 LoggingConfiguration 属性并设置 TargetBucket 和可选的 TargetPrefix，为 OSS 存储空间启用日志转存。",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	not has_logging_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LoggingConfiguration"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

has_logging_enabled(resource) if {
	helpers.has_property(resource, "LoggingConfiguration")
	logging_config := resource.Properties.LoggingConfiguration
	logging_config.TargetBucket != null
}
