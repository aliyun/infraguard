package infraguard.packs.aliyun.mlps_level_2_pre_check_compliance_pack

import rego.v1

pack_meta := {
	"id": "mlps-level-2-pre-check-compliance-pack",
	"name": {
		"en": "MLPS Level 2 Pre-check Compliance Pack",
		"zh": "等保二级预检合规包",
		"ja": "MLPS レベル 2 事前チェックコンプライアンスパック",
		"de": "MLPS Level 2 Vorprüfung Compliance-Paket",
		"es": "Paquete de Cumplimiento de Verificación Previa MLPS Nivel 2",
		"fr": "Pack de Conformité de Vérification Préalable MLPS Niveau 2",
		"pt": "Pacote de Conformidade de Verificação Prévia MLPS Nível 2",
	},
	"description": {
		"en": "Compliance pack for MLPS level 2 pre-check",
		"zh": "等保二级预检合规包",
		"ja": "MLPS レベル 2 事前チェック用のコンプライアンスパック",
		"de": "Compliance-Paket für MLPS Level 2 Vorprüfung",
		"es": "Paquete de cumplimiento para verificación previa MLPS nivel 2",
		"fr": "Pack de conformité pour vérification préalable MLPS niveau 2",
		"pt": "Pacote de conformidade para verificação prévia MLPS nível 2",
	},
	"rules": [
		# "use-ddos-instance-for-security-protection",
		# "use-cloud-fire-wall-for-security-protection",
		# "security-center-defense-config-check",
		"use-waf-instance-for-security-protection",
		"actiontrail-trail-intact-enabled",
		# "ram-password-require-char-check",  # Commented: ROS does not support ALIYUN::RAM::PasswordPolicy resource type
		# "ram-password-max-age-check",  # Commented: ROS does not support ALIYUN::RAM::PasswordPolicy resource type
		# "ram-password-max-login-attemps-check",  # Commented: ROS does not support ALIYUN::RAM::PasswordPolicy resource type
		"security-center-version-check",
		# "adb-cluster-audit-log-enabled",  # Commented: ROS ADB::DBCluster does not support AuditLog property
		# "alb-all-listener-enabled-acl",  # Commented: ROS ALB::Listener does not support AclConfig property
		# "cen-cross-region-bandwidth-check",
		# "cr-instance-any-ip-access-check",
		"ecs-disk-auto-snapshot-policy",
		"ecs-instance-enabled-security-protection",
		# "ecs-instance-updated-security-vul",  # Commented: ROS ECS::Instance does not support Vulnerabilities property
		"sg-public-access-check",
		"ecs-security-group-risky-ports-check-with-protocol",
		"eip-bandwidth-limit",
		"elasticsearch-public-and-any-ip-access-check",
		# "natgateway-snat-eip-bandwidth-check",
		# "nat-risk-ports-check",
		"oss-bucket-policy-no-any-anonymous",
		"oss-bucket-authorize-specified-ip",
		"ram-group-has-member-check",
		"ram-policy-no-statements-with-admin-access-check",
		# "ram-policy-in-use-check",
		"ram-user-last-login-expired-check",
		"ram-user-no-policy-check",
		"ram-user-ak-used-expired-check",
		"ram-user-login-check",
		"rds-public-connection-and-any-ip-access-check",
		"rds-instance-enabled-auditing",
		"redis-instance-open-auth-mode",
		"slb-acl-public-access-check",
		# "slb-all-listener-enabled-acl",
		"slb-loadbalancer-bandwidth-limit",
		"vpc-network-acl-risky-ports-check",
		"vpc-flow-logs-enabled",
		# "waf3-instance-enabled-specified-defense-rules",
	],
}
