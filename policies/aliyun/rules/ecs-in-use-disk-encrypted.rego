package infraguard.rules.aliyun.ecs_in_use_disk_encrypted

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ecs-in-use-disk-encrypted",
	"name": {
		"en": "ECS In-Use Disk Encryption",
		"zh": "使用中的 ECS 数据磁盘开启加密",
	},
	"severity": "medium",
	"description": {
		"en": "ECS data disks should have encryption enabled to protect data at rest. Encrypted disks use KMS keys to encrypt data, ensuring data security and compliance with regulatory requirements.",
		"zh": "使用中的 ECS 数据磁盘应开启加密以保护静态数据。加密磁盘使用 KMS 密钥对数据进行加密，确保数据安全并符合合规要求。",
	},
	"reason": {
		"en": "The ECS disk does not have encryption enabled, which may expose sensitive data to unauthorized access.",
		"zh": "ECS 磁盘未开启加密，可能导致敏感数据暴露给未授权访问。",
	},
	"recommendation": {
		"en": "Enable encryption for the ECS disk by setting the Encrypted property to true.",
		"zh": "通过将 Encrypted 属性设置为 true 来为 ECS 磁盘启用加密。",
	},
	"resource_types": ["ALIYUN::ECS::Disk"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")
	not is_encrypted(resource)
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

is_encrypted(resource) if {
	resource.Properties.Encrypted == true
}
