package infraguard.rules.aliyun.oss_bucket_public_read_prohibited

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "oss-bucket-public-read-prohibited",
	"name": {
		"en": "OSS Bucket Public Read Prohibited",
		"zh": "OSS 存储空间 ACL 不开启公共读",
	},
	"severity": "high",
	"description": {
		"en": "OSS buckets should not allow public read access unless specifically required. Public read access allows anyone to access and download objects in the bucket.",
		"zh": "除非特别需要，OSS 存储空间不应允许公共读取访问。公共读取访问允许任何人访问和下载存储空间中的对象。",
	},
	"reason": {
		"en": "The OSS bucket has public read access enabled, which may expose sensitive data to unauthorized access.",
		"zh": "OSS 存储空间启用了公共读取访问，可能导致敏感数据暴露给未授权访问。",
	},
	"recommendation": {
		"en": "Change the bucket ACL to private by setting the AccessControl property to 'private'.",
		"zh": "通过将 AccessControl 属性设置为'private'，将存储空间 ACL 更改为私有。",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	is_public_read(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AccessControl"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

is_public_read(resource) if {
	resource.Properties.AccessControl in ["public-read", "public-read-write"]
}
