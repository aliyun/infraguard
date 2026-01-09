package infraguard.rules.aliyun.oss_bucket_anonymous_prohibited

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:oss-bucket-anonymous-prohibited",
	"name": {
		"en": "OSS Bucket Anonymous Access Prohibited",
		"zh": "OSS 存储桶禁用匿名访问",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that anonymous access is prohibited for the OSS bucket.",
		"zh": "确保 OSS 存储桶禁用了匿名访问。",
	},
	"reason": {
		"en": "Anonymous access to an OSS bucket increases the risk of unauthorized data exposure.",
		"zh": "对 OSS 存储桶的匿名访问增加了数据未经授权泄露的风险。",
	},
	"recommendation": {
		"en": "Configure the OSS bucket ACL to 'private' and ensure no public read/write permissions are granted to anonymous users.",
		"zh": "将 OSS 存储桶 ACL 配置为'private'，并确保未向匿名用户授予公开读写权限。",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")

	# Conceptual check for public access
	acl := helpers.get_property(resource, "AccessControlList", "private")
	acl != "private"
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AccessControlList"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
