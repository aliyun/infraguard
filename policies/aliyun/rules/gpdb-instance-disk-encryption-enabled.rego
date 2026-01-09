package infraguard.rules.aliyun.gpdb_instance_disk_encryption_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:gpdb-instance-disk-encryption-enabled",
	"name": {
		"en": "GPDB Disk Encryption Enabled",
		"zh": "GPDB 开启磁盘加密"
	},
	"severity": "high",
	"description": {
		"en": "Ensures GPDB instances have disk encryption enabled.",
		"zh": "确保 GPDB 实例开启了磁盘加密。"
	},
	"reason": {
		"en": "Encryption at rest protects sensitive database files from unauthorized access.",
		"zh": "静态加密保护敏感数据库文件免受未经授权的访问。"
	},
	"recommendation": {
		"en": "Enable disk encryption using KMS for the GPDB instance.",
		"zh": "使用 KMS 为 GPDB 实例开启磁盘加密。"
	},
	"resource_types": ["ALIYUN::GPDB::DBInstance"],
}

is_compliant(resource) if {
	# EncryptionKey being set usually indicates encryption is enabled.
	helpers.has_property(resource, "EncryptionKey")
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::GPDB::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EncryptionKey"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
