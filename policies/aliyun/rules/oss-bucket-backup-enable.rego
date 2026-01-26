package infraguard.rules.aliyun.oss_bucket_backup_enable

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "oss-bucket-backup-enable",
	"name": {
		"en": "OSS Backup Enabled",
		"zh": "OSS 开启备份"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures OSS buckets have backup or versioning enabled.",
		"zh": "确保 OSS 存储桶开启了备份或版本控制。"
	},
	"reason": {
		"en": "Backups and versioning prevent data loss from accidental deletion or modification.",
		"zh": "备份和版本控制可防止因意外删除或修改导致的数据丢失。"
	},
	"recommendation": {
		"en": "Enable versioning or cross-region replication for the OSS bucket.",
		"zh": "为 OSS 存储桶开启版本控制或跨区域复制。"
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

is_compliant(resource) if {
	# Versioning check
	v := helpers.get_property(resource, "VersioningConfiguration", {})
	v.Status == "Enabled"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VersioningConfiguration"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
