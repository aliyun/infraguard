package infraguard.packs.aliyun.oss_compliance_management_best_practice

import rego.v1

pack_meta := {
	"id": "oss-compliance-management-best-practice",
	"name": {
		"en": "OSS Compliance Management Best Practice",
		"zh": "OSS 合规管理最佳实践",
	},
	"description": {
		"en": "Best practices for OSS bucket compliance management, covering access control, encryption, logging, versioning, and security policies.",
		"zh": "OSS 存储空间合规管理最佳实践,涵盖访问控制、加密、日志、版本控制和安全策略。",
	},
	"rules": [
		"oss-bucket-public-read-prohibited",
		"oss-bucket-public-write-prohibited",
		"oss-bucket-server-side-encryption-enabled",
		"oss-zrs-enabled",
		"oss-bucket-policy-no-any-anonymous",
		"oss-bucket-logging-enabled",
		"oss-bucket-versioning-enabled",
		"oss-bucket-policy-outside-organization-check",
		"oss-bucket-referer-limit",
	],
}
