package infraguard.packs.aliyun.ai_model_training_architecture_best_practice

import rego.v1

pack_meta := {
	"id": "ai-model-training-architecture-best-practice",
	"name": {
		"en": "AI Model Training Architecture Best Practice",
		"zh": "AI 模型训练架构检测最佳实践",
	},
	"description": {
		"en": "Best practices for AI model training architecture, covering ACK, ECS, NAS, OSS, VPC, and other resources.",
		"zh": "AI 模型训练架构最佳实践,涵盖 ACK、ECS、NAS、OSS、VPC 等资源。",
	},
	"rules": [
		"ack-cluster-upgrade-latest-version",
		"ack-cluster-supported-version",
		"ack-cluster-encryption-enabled",
		"cr-instance-multi-zone",
		# "cr-instance-public-access-check",  # Commented: ROS CR::Instance does not support PublicNetworkAccess property
		"cr-repository-immutablity-enable",
		"ecs-disk-encrypted",
		"ecs-disk-auto-snapshot-policy",
		# "ecs-instance-monitor-enabled",  # Commented: ROS ECS::Instance does not support CloudMonitorFlags property
		"ecs-instance-image-expired-check",
		# "ecs-instance-status-no-stopped",  # Commented: ROS ECS::Instance does not support Status property
		"ecs-instance-ram-role-attached",
		"ecs-instance-not-bind-key-pair",
		"kms-key-rotation-enabled",
		"kms-key-delete-protection-enabled",
		"kms-secret-rotation-enabled",
		"nas-filesystem-mount-target-access-group-check",
		# "nas-filesystem-enable-backup-plan",
		# "nas-filesystem-access-point-enabled-ram",  # Commented: ROS does not support ALIYUN::NAS::AccessPoint resource type
		"nas-filesystem-encrypt-type-check",
		# "nas-filesystem-access-point-root-directory-check",  # Commented: ROS does not support ALIYUN::NAS::AccessPoint resource type
		"oss-default-encryption-kms",
		"oss-bucket-tls-version-check",
		# "oss-bucket-remote-replication",  # Commented: ROS template does not support ReplicationConfiguration
		"oss-bucket-only-https-enabled",
		"pai-eas-instances-multi-zone",
		# "vpc-secondary-cidr-route-check",
		"vpc-flow-logs-enabled",
		"vswitch-available-ip-count",
		"sls-project-multi-zone",
	],
}
