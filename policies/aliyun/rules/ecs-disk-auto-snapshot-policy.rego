package infraguard.rules.aliyun.ecs_disk_auto_snapshot_policy

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-disk-auto-snapshot-policy",
	"name": {
		"en": "ECS disk has auto snapshot policy configured",
		"zh": "ECS 磁盘设置自动快照策略",
	},
	"description": {
		"en": "ECS disk has auto snapshot policy configured, considered compliant. Disks not in use, disks that do not support auto snapshot policy, and non-persistent disks mounted by ACK clusters are not applicable. After enabling auto snapshot policy, Alibaba Cloud will automatically create snapshots for cloud disks according to preset time points and cycles, enabling quick recovery from virus intrusion or ransomware attacks.",
		"zh": "ECS 磁盘设置了自动快照策略,视为合规。状态非使用中的磁盘、不支持设置自动快照策略的磁盘、ACK 集群挂载的非持久化使用场景的磁盘视为不适用。开启自动快照策略后,阿里云会自动按照预设的时间点和周期为云盘创建快照,遭遇病毒入侵或勒索后能够快速从安全事件中恢复。",
	},
	"severity": "low",
	"resource_types": ["ALIYUN::ECS::Disk"],
	"reason": {
		"en": "ECS disk does not have auto snapshot policy configured",
		"zh": "ECS 磁盘未设置自动快照策略",
	},
	"recommendation": {
		"en": "Configure auto snapshot policy for ECS disk to enable automatic backup and quick recovery from security incidents",
		"zh": "为 ECS 磁盘配置自动快照策略以启用自动备份并快速从安全事件中恢复",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")

	# Check if AutoSnapshotPolicyId is configured
	not helpers.has_property(resource, "AutoSnapshotPolicyId")

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
