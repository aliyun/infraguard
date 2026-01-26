package infraguard.rules.aliyun.oss_bucket_public_write_prohibited

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "oss-bucket-public-write-prohibited",
	"name": {
		"en": "OSS Bucket Public Write Prohibited",
		"zh": "OSS 存储空间 ACL 不开启公共读写",
	},
	"severity": "high",
	"description": {
		"en": "OSS buckets should not allow public write access. Public write access allows anyone to upload, modify, or delete objects in the bucket, which poses significant security risks.",
		"zh": "OSS 存储空间不应允许公共写入访问。公共写入访问允许任何人上传、修改或删除存储空间中的对象，这会带来重大安全风险。",
	},
	"reason": {
		"en": "The OSS bucket has public write access enabled (public-read-write ACL), which allows unauthorized users to modify or delete data.",
		"zh": "OSS 存储空间启用了公共写入访问（public-read-write ACL），允许未授权用户修改或删除数据。",
	},
	"recommendation": {
		"en": "Change the bucket ACL to private or public-read by setting the AccessControl property to 'private' or 'public-read'.",
		"zh": "通过将 AccessControl 属性设置为'private'或'public-read'，将存储空间 ACL 更改为私有或公共读。",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	is_public_write(resource)
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

is_public_write(resource) if {
	resource.Properties.AccessControl == "public-read-write"
}
