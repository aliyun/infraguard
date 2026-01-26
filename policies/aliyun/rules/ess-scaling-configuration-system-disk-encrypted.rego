package infraguard.rules.aliyun.ess_scaling_configuration_system_disk_encrypted

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ess-scaling-configuration-system-disk-encrypted",
	"name": {
		"en": "ESS Scaling Configuration System Disk Encryption",
		"zh": "弹性伸缩配置中设置系统磁盘加密",
	},
	"severity": "high",
	"description": {
		"en": "ESS scaling configurations should enable system disk encryption to protect system data at rest.",
		"zh": "弹性伸缩配置中系统磁盘配置设置为加密，视为合规。",
	},
	"reason": {
		"en": "The ESS scaling configuration does not have system disk encryption enabled.",
		"zh": "弹性伸缩配置中的系统磁盘未加密，静态数据可能面临泄露风险。",
	},
	"recommendation": {
		"en": "Enable system disk encryption in the scaling configuration settings.",
		"zh": "在伸缩配置中启用系统磁盘加密功能。",
	},
	"resource_types": ["ALIYUN::ESS::ScalingConfiguration"],
}

# Check if system disk encryption is enabled
is_system_disk_encrypted(resource) if {
	system_disk_encrypted := helpers.get_property(resource, "SystemDiskEncryptAlgorithm", "")
	system_disk_encrypted != ""
}

is_system_disk_encrypted(resource) if {
	kms_key_id := helpers.get_property(resource, "SystemDiskKMSKeyId", "")
	kms_key_id != ""
}

# If no explicit encryption setting, consider it non-compliant
# Note: Some images have default encryption, but explicit configuration is preferred
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingConfiguration")
	not is_system_disk_encrypted(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SystemDiskEncryptAlgorithm"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
