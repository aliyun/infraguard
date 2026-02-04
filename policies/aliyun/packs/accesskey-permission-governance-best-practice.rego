package infraguard.packs.aliyun.accesskey_permission_governance_best_practice

import rego.v1

pack_meta := {
	"id": "accesskey-permission-governance-best-practice",
	"name": {
		"en": "AccessKey and Permission Governance Best Practice",
		"zh": "AccessKey 及权限治理最佳实践",
		"ja": "AccessKey および権限ガバナンスのベストプラクティス",
		"de": "AccessKey- und Berechtigungs-Governance Best Practices",
		"es": "Mejores Prácticas de Gobernanza de AccessKey y Permisos",
		"fr": "Meilleures Pratiques de Gouvernance des AccessKey et des Permissions",
		"pt": "Melhores Práticas de Governança de AccessKey e Permissões",
	},
	"description": {
		"en": "Best practices for AccessKey and permission governance",
		"zh": "AccessKey 及权限治理最佳实践",
		"ja": "AccessKey および権限ガバナンスのベストプラクティス",
		"de": "Best Practices für AccessKey- und Berechtigungs-Governance",
		"es": "Mejores prácticas para la gobernanza de AccessKey y permisos",
		"fr": "Meilleures pratiques pour la gouvernance des AccessKey et des permissions",
		"pt": "Melhores práticas para governança de AccessKey e permissões",
	},
	"rules": [
		"ram-password-policy-check",
		"root-mfa-check",
		"root-ak-check",
		"actiontrail-trail-intact-enabled",
		"ack-cluster-rrsa-enabled",
		"ecs-instance-ram-role-attached",
		"fc-service-bind-role",
		"ram-policy-no-statements-with-admin-access-check",
		"ram-user-ak-create-date-expired-check",
		"ram-user-mfa-check",
		"ram-user-last-login-expired-check",
		"ram-user-activated-ak-quantity-check",
		"ram-user-ak-used-expired-check",
		"ram-user-login-check",
	],
}
