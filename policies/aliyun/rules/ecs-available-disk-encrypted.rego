package infraguard.rules.aliyun.ecs_available_disk_encrypted

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ecs-available-disk-encrypted",
	"name": {
		"en": "ECS Disk Encryption Enabled",
		"zh": "可用的磁盘均已加密"
	},
	"severity": "high",
	"description": {
		"en": "Ensures that all ECS disks are encrypted.",
		"zh": "确保所有 ECS 磁盘都已加密。"
	},
	"reason": {
		"en": "Encryption protects data at rest from unauthorized physical access or theft.",
		"zh": "加密可以保护静态数据免受未经授权的物理访问或盗窃。"
	},
	"recommendation": {
		"en": "Set 'Encrypted' to true for all ECS disks.",
		"zh": "将所有 ECS 磁盘的'Encrypted'属性设置为 true。"
	},
	"resource_types": ["ALIYUN::ECS::Disk"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "Encrypted", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Encrypted"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
