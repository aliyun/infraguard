package infraguard.rules.aliyun.rds_instance_enabled_tde_disk_encryption

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "rds-instance-enabled-tde-disk-encryption",
	"name": {
		"en": "RDS Instance Enabled TDE or Disk Encryption",
		"zh": "RDS 实例开启 TDE 或者数据盘加密",
	},
	"severity": "medium",
	"description": {
		"en": "RDS instance should have TDE (Transparent Data Encryption) or disk encryption enabled.",
		"zh": "RDS 实例开启 TDE 或者数据盘加密，视为合规。",
	},
	"reason": {
		"en": "RDS instance does not have TDE or disk encryption enabled, which may expose data to security risks.",
		"zh": "RDS 实例未开启 TDE 或数据盘加密，可能导致数据面临安全风险。",
	},
	"recommendation": {
		"en": "Enable TDE by configuring EncryptionKey or use encrypted storage types (cloud_essd, cloud_essd2, cloud_essd3) for the RDS instance.",
		"zh": "通过配置 EncryptionKey 开启 TDE，或为 RDS 实例使用加密存储类型（cloud_essd、cloud_essd2、cloud_essd3）。",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance", "ALIYUN::RDS::PrepayDBInstance"],
}

# Encrypted storage types
encrypted_storage_types := ["cloud_essd", "cloud_essd2", "cloud_essd3"]

# Check if encryption is enabled (TDE via EncryptionKey or encrypted storage type)
is_encryption_enabled(resource) if {
	resource.Properties.EncryptionKey != null
}

is_encryption_enabled(resource) if {
	resource.Properties.DBInstanceStorageType in encrypted_storage_types
}

# Generate deny for non-compliant RDS instance resources
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_encryption_enabled(resource)
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
