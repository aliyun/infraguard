package infraguard.rules.aliyun.oss_bucket_versioning_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "oss-bucket-versioning-enabled",
	"name": {
		"en": "OSS Bucket Versioning Enabled",
		"zh": "OSS 存储桶开启版本控制",
	},
	"severity": "medium",
	"description": {
		"en": "OSS bucket should have versioning enabled to protect against accidental deletion or overwriting.",
		"zh": "OSS 存储桶开启版本控制，视为合规。",
	},
	"reason": {
		"en": "Versioning is not enabled for the OSS bucket, which increases the risk of data loss.",
		"zh": "OSS 存储桶未开启版本控制，增加了数据丢失的风险。",
	},
	"recommendation": {
		"en": "Enable versioning for the OSS bucket by setting VersioningConfiguration.Status to Enabled.",
		"zh": "通过将 VersioningConfiguration.Status 设置为 Enabled 来开启存储桶的版本控制。",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

# Check if versioning is enabled
is_versioning_enabled(resource) if {
	versioning := helpers.get_property(resource, "VersioningConfiguration", {})
	versioning.Status == "Enabled"
}

get_violation_path(resource) := ["Properties", "VersioningConfiguration", "Status"] if {
	helpers.has_property(resource, "VersioningConfiguration")
} else := ["Properties"]

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_versioning_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": get_violation_path(resource),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
