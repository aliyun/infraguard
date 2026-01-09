package infraguard.rules.aliyun.oss_bucket_remote_replication

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:oss-bucket-remote-replication",
	"name": {
		"en": "OSS Bucket Remote Replication Enabled",
		"zh": "OSS 存储桶开启跨区域复制",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that cross-region replication is enabled for the OSS bucket for disaster recovery.",
		"zh": "确保 OSS 存储桶开启了跨区域复制，以进行容灾。",
	},
	"reason": {
		"en": "Cross-region replication ensures data durability and availability in case of a regional failure.",
		"zh": "跨区域复制可确保在发生区域性故障时数据的持久性和可用性。",
	},
	"recommendation": {
		"en": "Enable cross-region replication for the OSS bucket.",
		"zh": "为 OSS 存储桶开启跨区域复制。",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")

	# Conceptual check
	not helpers.has_property(resource, "ReplicationConfiguration")
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
