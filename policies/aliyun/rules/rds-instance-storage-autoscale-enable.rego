package infraguard.rules.aliyun.rds_instance_storage_autoscale_enable

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rds-instance-storage-autoscale-enable",
	"name": {
		"en": "RDS Storage Autoscale Enabled",
		"zh": "RDS 开启存储自动扩容"
	},
	"severity": "low",
	"description": {
		"en": "Ensures RDS instances have storage autoscale enabled to prevent downtime due to full disks.",
		"zh": "确保 RDS 实例开启了存储自动扩容，以防止因磁盘满载导致的服务中断。"
	},
	"reason": {
		"en": "Automatic scaling ensures that the database doesn't run out of storage space.",
		"zh": "自动扩容确保数据库不会因存储空间耗尽而受限。"
	},
	"recommendation": {
		"en": "Set StorageAutoScale to 'Enable' for the RDS instance.",
		"zh": "为 RDS 实例将 StorageAutoScale 设置为 'Enable'。"
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

is_compliant(resource) if {
	helpers.get_property(resource, "StorageAutoScale", "Disable") == "Enable"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "StorageAutoScale"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
