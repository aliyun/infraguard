package infraguard.rules.aliyun.ecs_disk_all_encrypted_by_kms

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-disk-all-encrypted-by-kms",
	"name": {
		"en": "ECS disk with KMS encryption enabled",
		"zh": "ECS 磁盘开启 KMS 加密",
	},
	"description": {
		"en": "ECS disks (including system disk and data disks) are encrypted with KMS, considered compliant.",
		"zh": "ECS 磁盘(包括系统盘和数据盘)开启 KMS 加密，视为合规。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::Disk"],
	"reason": {
		"en": "ECS disk is not encrypted with KMS",
		"zh": "ECS 磁盘未开启 KMS 加密",
	},
	"recommendation": {
		"en": "Enable KMS encryption for ECS disks by setting Encrypted to true and specifying a KMSKeyId",
		"zh": "通过设置 Encrypted 为 true 并指定 KMSKeyId 来为 ECS 磁盘启用 KMS 加密",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")

	# Check if disk is encrypted
	encrypted := helpers.get_property(resource, "Encrypted", false)
	not helpers.is_true(encrypted)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Encrypted"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
