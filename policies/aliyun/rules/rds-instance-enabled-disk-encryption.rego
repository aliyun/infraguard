package infraguard.rules.aliyun.rds_instance_enabled_disk_encryption

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:rds-instance-enabled-disk-encryption",
	"name": {
		"en": "RDS Instance Disk Encryption Enabled",
		"zh": "RDS 实例开启磁盘加密"
	},
	"severity": "high",
	"description": {
		"en": "Ensures RDS instances have disk encryption enabled.",
		"zh": "确保 RDS 实例开启了磁盘加密。"
	},
	"reason": {
		"en": "Disk encryption protects the underlying data storage from unauthorized physical access.",
		"zh": "磁盘加密保护底层数据存储免受未经授权的物理访问。"
	},
	"recommendation": {
		"en": "Enable disk encryption for the RDS instance.",
		"zh": "为 RDS 实例开启磁盘加密。"
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

is_compliant(resource) if {
	# EncryptionKey being set usually indicates disk encryption is enabled.
	helpers.has_property(resource, "EncryptionKey")
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EncryptionKey"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
