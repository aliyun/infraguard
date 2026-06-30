package infraguard.packs.aliyun.generative_ai_compliance_best_practice

import rego.v1

pack_meta := {
	"id": "generative-ai-compliance-best-practice",
	"name": {
		"en": "Generative AI Compliance Best Practice",
		"zh": "生成式 AI 合规最佳实践",
		"ja": "生成 AI コンプライアンスのベストプラクティス",
		"de": "Generative KI-Compliance Best Practices",
		"es": "Mejores Prácticas de Cumplimiento de IA Generativa",
		"fr": "Meilleures Pratiques de Conformité pour l'IA Générative",
		"pt": "Melhores Práticas de Conformidade de IA Generativa"
	},
	"description": {
		"en": "This compliance pack aims to help you comprehensively detect and manage potential compliance risks in security and stability aspects of Bailian, PAI platform, and their dependent core products (such as ACK, ACR, OSS, NAS, KMS, SLS, MaxCompute, etc.).",
		"zh": "本合规包旨在帮助您全面检测和管理百炼、人工智能平台 PAI 以及其依赖的核心产品(如 ACK、ACR、OSS、NAS、KMS、SLS、MaxCompute 等)在安全与稳定性方面的潜在合规风险。",
		"ja": "このコンプライアンスパックは、Bailian、PAI プラットフォーム、およびそれらに依存するコア製品（ACK、ACR、OSS、NAS、KMS、SLS、MaxCompute など）のセキュリティと安定性の側面における潜在的なコンプライアンスリスクを包括的に検出および管理するのに役立ちます。",
		"de": "Dieses Compliance-Paket soll Ihnen helfen, potenzielle Compliance-Risiken in den Bereichen Sicherheit und Stabilität von Bailian, PAI-Plattform und ihren abhängigen Kernprodukten (wie ACK, ACR, OSS, NAS, KMS, SLS, MaxCompute usw.) umfassend zu erkennen und zu verwalten.",
		"es": "Este paquete de cumplimiento tiene como objetivo ayudarle a detectar y gestionar de manera integral los riesgos potenciales de cumplimiento en los aspectos de seguridad y estabilidad de Bailian, la plataforma PAI y sus productos principales dependientes (como ACK, ACR, OSS, NAS, KMS, SLS, MaxCompute, etc.).",
		"fr": "Ce pack de conformité vise à vous aider à détecter et gérer de manière exhaustive les risques potentiels de conformité dans les aspects de sécurité et de stabilité de Bailian, de la plateforme PAI et de leurs produits principaux dépendants (tels que ACK, ACR, OSS, NAS, KMS, SLS, MaxCompute, etc.).",
		"pt": "Este pacote de conformidade visa ajudá-lo a detectar e gerenciar de forma abrangente os riscos potenciais de conformidade nos aspectos de segurança e estabilidade da plataforma Bailian, PAI e seus produtos principais dependentes (como ACK, ACR, OSS, NAS, KMS, SLS, MaxCompute, etc.)."
	},
	"rules": [
		# "cr-instance-public-access-check",  # Commented: ROS CR::Instance does not support PublicNetworkAccess property,
		"cr-repository-immutablity-enable",
		"ecs-disk-auto-snapshot-policy",
		"ecs-disk-encrypted",
		"kms-key-delete-protection-enabled",
		"kms-key-rotation-enabled",
		"kms-secret-rotation-enabled",
		"maxcompute-project-encryption-enabled",
		"maxcompute-project-ip-whitelist-enabled",
		# "maxcompute-project-multi-zone",
		# "nas-filesystem-access-point-enabled-ram",  # Commented: ROS does not support ALIYUN::NAS::AccessPoint resource type,
		# "nas-filesystem-enable-backup-plan",
		"nas-filesystem-encrypt-type-check",
		"nas-filesystem-mount-target-access-group-check",
		"oss-bucket-only-https-enabled",
		# "oss-bucket-remote-replication",  # ROS template does not support replication configuration,
		# "oss-bucket-tls-version-check",  # ROS template does not support TLS version configuration,
		"oss-default-encryption-kms",
		"pai-eas-instances-multi-zone"
	]
}
