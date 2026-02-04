# Security Group Best Practice Pack
# A collection of rules for checking security group compliance to reduce security risks.
package infraguard.packs.aliyun.security_group_best_practice

import rego.v1

# Pack metadata with i18n support
pack_meta := {
	"id": "security-group-best-practice",
	"name": {
		"en": "Security Group Best Practice",
		"zh": "安全组最佳实践",
		"ja": "セキュリティグループのベストプラクティス",
		"de": "Sicherheitsgruppe Best Practices",
		"es": "Mejores Prácticas de Grupo de Seguridad",
		"fr": "Meilleures Pratiques de Groupe de Sécurité",
		"pt": "Melhores Práticas de Grupo de Segurança",
	},
	"description": {
		"en": "Continuously check security group rules for compliance to reduce security risks.",
		"zh": "持续检查安全组规则的合规性，降低安全风险。",
		"ja": "セキュリティリスクを低減するために、セキュリティグループルールのコンプライアンスを継続的にチェックします。",
		"de": "Kontinuierliche Überprüfung der Sicherheitsgruppen-Regeln auf Compliance, um Sicherheitsrisiken zu reduzieren.",
		"es": "Verificar continuamente las reglas del grupo de seguridad para cumplimiento y reducir los riesgos de seguridad.",
		"fr": "Vérifier continuellement les règles du groupe de sécurité pour la conformité et réduire les risques de sécurité.",
		"pt": "Verificar continuamente as regras do grupo de segurança para conformidade e reduzir riscos de segurança.",
	},
	"rules": [
		"ecs-instance-attached-security-group",
		"ecs-security-group-white-list-port-check",
		"sg-public-access-check",
		"ecs-security-group-not-open-all-port",
		"ecs-security-group-not-open-all-protocol",
		"ecs-security-group-not-internet-cidr-access",
		"ecs-security-group-egress-not-all-access",
		"ecs-security-group-risky-ports-check-with-protocol",
	],
}
