package infraguard.packs.aliyun.ecs_compliance_management_best_practice

import rego.v1

pack_meta := {
	"id": "ecs-compliance-management-best-practice",
	"name": {
		"en": "ECS Compliance Management Best Practice",
		"zh": "ECS 合规管理最佳实践",
		"ja": "ECS コンプライアンス管理のベストプラクティス",
		"de": "ECS-Compliance-Management Best Practices",
		"es": "Mejores Prácticas de Gestión de Cumplimiento de ECS",
		"fr": "Meilleures Pratiques de Gestion de la Conformité ECS",
		"pt": "Melhores Práticas de Gestão de Conformidade ECS"
	},
	"description": {
		"en": "Best practices for ECS compliance management",
		"zh": "ECS 合规管理最佳实践",
		"ja": "ECS コンプライアンス管理のベストプラクティス",
		"de": "Best Practices für das ECS-Compliance-Management",
		"es": "Mejores prácticas para la gestión de cumplimiento de ECS",
		"fr": "Meilleures pratiques pour la gestion de la conformité ECS",
		"pt": "Melhores práticas para gestão de conformidade ECS"
	},
	"rules": [
		# "ecs-all-enabled-security-protection",
		# "ecs-all-updated-security-vul",
		"ecs-disk-auto-snapshot-policy",
		"ecs-disk-encrypted",
		# "ecs-disk-in-use",
		# "ecs-disk-no-lock",  # Removed: Status is a runtime attribute, cannot be checked in templates,
		# "ecs-disk-retain-auto-snapshot",
		"ecs-instance-attached-security-group",
		"ecs-instance-deletion-protection-enabled",
		"ecs-instance-expired-check",
		# "ecs-instance-imageId-check",
		# "ecs-instance-no-lock",
		# "ecs-instance-status-no-stopped",  # Commented: ROS ECS::Instance does not support Status property,
		"ecs-instances-in-vpc",
		"ecs-security-group-risky-ports-check-with-protocol",
		"ecs-snapshot-retention-days",
		# "ess-group-health-check",
		"sg-public-access-check"
	]
}
