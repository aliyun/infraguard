package infraguard.packs.aliyun.generative_ai_compliance_best_practice

import rego.v1

pack_meta := {
	"id": "generative-ai-compliance-best-practice",
	"name": {
		"en": "Generative AI Compliance Best Practice",
		"zh": "生成式 AI 合规最佳实践",
	},
	"description": {
		"en": "This compliance pack aims to help you comprehensively detect and manage potential compliance risks in security and stability aspects of Bailian, PAI platform, and their dependent core products (such as ACK, ACR, OSS, NAS, KMS, SLS, MaxCompute, etc.).",
		"zh": "本合规包旨在帮助您全面检测和管理百炼、人工智能平台 PAI 以及其依赖的核心产品(如 ACK、ACR、OSS、NAS、KMS、SLS、MaxCompute 等)在安全与稳定性方面的潜在合规风险。",
	},
	"rules": [
		# "cr-instance-public-access-check",  # Commented: ROS CR::Instance does not support PublicNetworkAccess property
		"cr-repository-immutablity-enable",
		"ecs-disk-encrypted",
		"ecs-disk-auto-snapshot-policy",
		"kms-key-rotation-enabled",
		"kms-key-delete-protection-enabled",
		"kms-secret-rotation-enabled",
		# "maxcompute-project-multi-zone",
		"maxcompute-project-encryption-enabled",
		"maxcompute-project-ip-whitelist-enabled",
		"nas-filesystem-mount-target-access-group-check",
		# "nas-filesystem-enable-backup-plan",
		# "nas-filesystem-access-point-enabled-ram",  # Commented: ROS does not support ALIYUN::NAS::AccessPoint resource type
		"nas-filesystem-encrypt-type-check",
		"oss-default-encryption-kms",
		# "oss-bucket-tls-version-check",  # ROS template does not support TLS version configuration
		# "oss-bucket-remote-replication",  # ROS template does not support replication configuration
		"oss-bucket-only-https-enabled",
		"pai-eas-instances-multi-zone",
	],
}
