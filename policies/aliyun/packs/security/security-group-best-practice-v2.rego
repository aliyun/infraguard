package infraguard.packs.aliyun.security_group_best_practice_v2

import rego.v1

pack_meta := {
	"id": "security-group-best-practice-v2",
	"name": {
		"en": "Security Group Best Practice",
		"zh": "安全组最佳实践",
		"ja": "セキュリティグループのベストプラクティス",
		"de": "Sicherheitsgruppe Best Practices",
		"es": "Mejores Prácticas de Grupo de Seguridad",
		"fr": "Meilleures Pratiques de Groupe de Sécurité",
		"pt": "Melhores Práticas de Grupo de Segurança"
	},
	"description": {
		"en": "Best practices for ECS security group configuration to ensure network security and access control. Includes checks for risky ports, access restrictions, and security group settings.",
		"zh": "ECS 安全组配置最佳实践，确保网络安全和访问控制。包括危险端口检查、访问限制和安全组设置检查。",
		"ja": "ネットワークセキュリティとアクセス制御を確保するための ECS セキュリティグループ設定のベストプラクティス。リスクのあるポート、アクセス制限、セキュリティグループ設定のチェックが含まれます。",
		"de": "Best Practices für die ECS-Sicherheitsgruppen-Konfiguration, um Netzwerksicherheit und Zugriffskontrolle sicherzustellen. Enthält Prüfungen für riskante Ports, Zugriffsbeschränkungen und Sicherheitsgruppen-Einstellungen.",
		"es": "Mejores prácticas para la configuración de grupos de seguridad ECS para garantizar la seguridad de la red y el control de acceso. Incluye verificaciones de puertos riesgosos, restricciones de acceso y configuraciones de grupos de seguridad.",
		"fr": "Meilleures pratiques pour la configuration des groupes de sécurité ECS afin d'assurer la sécurité du réseau et le contrôle d'accès. Inclut les vérifications des ports à risque, les restrictions d'accès et les configurations des groupes de sécurité.",
		"pt": "Melhores práticas para configuração de grupo de segurança ECS para garantir segurança de rede e controle de acesso. Inclui verificações de portas de risco, restrições de acesso e configurações de grupo de segurança."
	},
	"rules": [
		"ecs-instance-attached-security-group",
		"ecs-security-group-egress-not-all-access",
		"ecs-security-group-not-internet-cidr-access",
		"ecs-security-group-not-open-all-port",
		"ecs-security-group-not-open-all-protocol",
		"ecs-security-group-risky-ports-check-with-protocol",
		"ecs-security-group-white-list-port-check",
		"sg-public-access-check"
	]
}
