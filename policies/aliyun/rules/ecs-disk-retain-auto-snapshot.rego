package infraguard.rules.aliyun.ecs_disk_retain_auto_snapshot

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ecs-disk-retain-auto-snapshot",
	"name": {
		"en": "Retain auto snapshot when ECS disk is released",
		"zh": "ECS 数据磁盘释放时保留自动快照",
	},
	"description": {
		"en": "Configure ECS disks to retain auto snapshots when released, considered compliant. This helps protect data from accidental deletion.",
		"zh": "设置 ECS 磁盘释放时保留自动快照，视为合规。这有助于防止数据意外删除。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::Disk"],
	"reason": {
		"en": "ECS disk will delete auto snapshots when released, risking data loss",
		"zh": "ECS 磁盘释放时将删除自动快照，可能导致数据丢失",
	},
	"recommendation": {
		"en": "Set DeleteAutoSnapshot to false to retain auto snapshots when disk is released",
		"zh": "将 DeleteAutoSnapshot 设置为 false 以在磁盘释放时保留自动快照",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")

	# Check if auto snapshots will be retained
	delete_auto_snapshot := helpers.get_property(resource, "DeleteAutoSnapshot", false)
	helpers.is_true(delete_auto_snapshot)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeleteAutoSnapshot"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
