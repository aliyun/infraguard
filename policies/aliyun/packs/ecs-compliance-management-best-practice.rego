package infraguard.packs.aliyun.ecs_compliance_management_best_practice

import rego.v1

pack_meta := {
	"id": "ecs-compliance-management-best-practice",
	"name": {
		"en": "ECS Compliance Management Best Practice",
		"zh": "ECS 合规管理最佳实践",
	},
	"description": {
		"en": "Best practices for ECS compliance management",
		"zh": "ECS 合规管理最佳实践",
	},
	"rules": [
		# "ecs-all-updated-security-vul",
		# "ecs-all-enabled-security-protection",
		"ecs-snapshot-retention-days",
		# "ecs-disk-no-lock",  # Removed: Status is a runtime attribute, cannot be checked in templates
		"ecs-disk-encrypted",
		# "ecs-disk-in-use",
		"ecs-disk-auto-snapshot-policy",
		# "ecs-disk-retain-auto-snapshot",
		"ecs-instance-expired-check",
		"ecs-instance-deletion-protection-enabled",
		"ecs-instance-attached-security-group",
		# "ecs-instance-no-lock",
		# "ecs-instance-status-no-stopped",  # Commented: ROS ECS::Instance does not support Status property
		"ecs-instances-in-vpc",
		# "ecs-instance-imageId-check",
		"sg-public-access-check",
		"ecs-security-group-risky-ports-check-with-protocol",
		# "ess-group-health-check",
	],
}
