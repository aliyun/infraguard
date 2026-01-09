package infraguard.rules.aliyun.ess_scaling_configuration_data_disk_encrypted

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:ess-scaling-configuration-data-disk-encrypted",
	"name": {
		"en": "ESS Scaling Configuration Data Disk Encryption",
		"zh": "弹性伸缩配置中设置数据磁盘加密",
	},
	"severity": "high",
	"description": {
		"en": "ESS scaling configurations should enable data disk encryption to protect data at rest.",
		"zh": "弹性伸缩配置中数据磁盘配置均设置为加密，视为合规。",
	},
	"reason": {
		"en": "The ESS scaling configuration has data disks that are not encrypted, which may expose sensitive data at rest.",
		"zh": "弹性伸缩配置中的数据磁盘未加密，静态数据可能面临泄露风险。",
	},
	"recommendation": {
		"en": "Enable encryption for all data disks in the scaling configuration by setting DiskMappings[*].Encrypted to true.",
		"zh": "在伸缩配置中，将所有数据磁盘的 DiskMappings[*].Encrypted 设置为 true 以启用加密。",
	},
	"resource_types": ["ALIYUN::ESS::ScalingConfiguration"],
}

# Check if all data disks are encrypted
all_data_disks_encrypted(resource) if {
	disk_mappings := helpers.get_property(resource, "DiskMappings", [])
	disk_mappings == []
}

all_data_disks_encrypted(resource) if {
	disk_mappings := helpers.get_property(resource, "DiskMappings", [])
	disk_mappings != []
	every disk in disk_mappings {
		disk.Encrypted == true
	}
}

all_data_disks_encrypted(resource) if {
	disk_mappings := helpers.get_property(resource, "DiskMappings", [])
	disk_mappings != []
	every disk in disk_mappings {
		disk.Encrypted == "true"
	}
}

# Deny rule: ESS scaling configurations must have all data disks encrypted
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingConfiguration")
	not all_data_disks_encrypted(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DiskMappings"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
