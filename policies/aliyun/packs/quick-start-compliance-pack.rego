package infraguard.packs.aliyun.quick_start_compliance_pack

import rego.v1

pack_meta := {
	"id": "quick-start-compliance-pack",
	"name": {
		"en": "Quick Start Compliance Pack",
		"zh": "快速体验合规包",
		"ja": "クイックスタートコンプライアンスパック",
		"de": "Schnellstart-Compliance-Paket",
		"es": "Paquete de Cumplimiento de Inicio Rápido",
		"fr": "Pack de Conformité de Démarrage Rapide",
		"pt": "Pacote de Conformidade de Início Rápido",
	},
	"description": {
		"en": "A quick start compliance pack covering basic security best practices for ECS, OSS, RAM, and RDS.",
		"zh": "快速体验合规包,涵盖 ECS、OSS、RAM 和 RDS 的基本安全最佳实践。",
		"ja": "ECS、OSS、RAM、RDS の基本的なセキュリティベストプラクティスをカバーするクイックスタートコンプライアンスパック。",
		"de": "Ein Schnellstart-Compliance-Paket, das grundlegende Sicherheits-Best-Practices für ECS, OSS, RAM und RDS abdeckt.",
		"es": "Un paquete de cumplimiento de inicio rápido que cubre las mejores prácticas básicas de seguridad para ECS, OSS, RAM y RDS.",
		"fr": "Un pack de conformité de démarrage rapide couvrant les meilleures pratiques de sécurité de base pour ECS, OSS, RAM et RDS.",
		"pt": "Um pacote de conformidade de início rápido cobrindo práticas básicas de segurança para ECS, OSS, RAM e RDS.",
	},
	"rules": [
		# "ecs-instance-no-public-ip",
		"oss-bucket-public-read-prohibited",
		"ram-policy-no-statements-with-admin-access-check",
		# "ram-user-mfa-check-v2",
		# "ram-user-ak-create-date-expired-check-v2",
		"ram-user-activated-ak-quantity-check",
		"rds-public-connection-and-any-ip-access-check",
	],
}
