package infraguard.packs.aliyun.ai_model_training_architecture_best_practice

import rego.v1

pack_meta := {
	"id": "ai-model-training-architecture-best-practice",
	"name": {
		"en": "AI Model Training Architecture Best Practice",
		"zh": "AI 模型训练架构检测最佳实践",
		"ja": "AI モデル訓練アーキテクチャのベストプラクティス",
		"de": "KI-Modelltrainingsarchitektur Best Practices",
		"es": "Mejores Prácticas de Arquitectura de Entrenamiento de Modelos de IA",
		"fr": "Meilleures Pratiques d'Architecture d'Entraînement de Modèles d'IA",
		"pt": "Melhores Práticas de Arquitetura de Treinamento de Modelos de IA"
	},
	"description": {
		"en": "Best practices for AI model training architecture, covering ACK, ECS, NAS, OSS, VPC, and other resources.",
		"zh": "AI 模型训练架构最佳实践,涵盖 ACK、ECS、NAS、OSS、VPC 等资源。",
		"ja": "AI モデル訓練アーキテクチャのベストプラクティス。ACK、ECS、NAS、OSS、VPC などのリソースをカバーします。",
		"de": "Best Practices für KI-Modelltrainingsarchitekturen, die ACK, ECS, NAS, OSS, VPC und andere Ressourcen abdecken.",
		"es": "Mejores prácticas para la arquitectura de entrenamiento de modelos de IA, que cubre ACK, ECS, NAS, OSS, VPC y otros recursos.",
		"fr": "Meilleures pratiques pour l'architecture d'entraînement de modèles d'IA, couvrant ACK, ECS, NAS, OSS, VPC et d'autres ressources.",
		"pt": "Melhores práticas para arquitetura de treinamento de modelos de IA, cobrindo ACK, ECS, NAS, OSS, VPC e outros recursos."
	},
	"rules": [
		"ack-cluster-encryption-enabled",
		"ack-cluster-supported-version",
		"ack-cluster-upgrade-latest-version",
		"cr-instance-multi-zone",
		# "cr-instance-public-access-check",  # Commented: ROS CR::Instance does not support PublicNetworkAccess property,
		"cr-repository-immutablity-enable",
		"ecs-disk-auto-snapshot-policy",
		"ecs-disk-encrypted",
		"ecs-instance-image-expired-check",
		# "ecs-instance-monitor-enabled",  # Commented: ROS ECS::Instance does not support CloudMonitorFlags property,
		"ecs-instance-not-bind-key-pair",
		"ecs-instance-ram-role-attached",
		# "ecs-instance-status-no-stopped",  # Commented: ROS ECS::Instance does not support Status property,
		"kms-key-delete-protection-enabled",
		"kms-key-rotation-enabled",
		"kms-secret-rotation-enabled",
		# "nas-filesystem-access-point-enabled-ram",  # Commented: ROS does not support ALIYUN::NAS::AccessPoint resource type,
		# "nas-filesystem-access-point-root-directory-check",  # Commented: ROS does not support ALIYUN::NAS::AccessPoint resource type,
		# "nas-filesystem-enable-backup-plan",
		"nas-filesystem-encrypt-type-check",
		"nas-filesystem-mount-target-access-group-check",
		"oss-bucket-only-https-enabled",
		# "oss-bucket-remote-replication",  # Commented: ROS template does not support ReplicationConfiguration,
		"oss-bucket-tls-version-check",
		"oss-default-encryption-kms",
		"pai-eas-instances-multi-zone",
		"sls-project-multi-zone",
		"vpc-flow-logs-enabled",
		# "vpc-secondary-cidr-route-check",
		"vswitch-available-ip-count"
	]
}
