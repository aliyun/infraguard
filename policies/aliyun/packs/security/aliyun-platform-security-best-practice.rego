package infraguard.packs.aliyun.aliyun_platform_security_best_practice

import rego.v1

pack_meta := {
	"id": "aliyun-platform-security-best-practice",
	"name": {
		"en": "Aliyun Platform Security Best Practice",
		"zh": "阿里云平台安全最佳实践",
		"ja": "Alibaba Cloud プラットフォームセキュリティのベストプラクティス",
		"de": "Alibaba Cloud Plattform-Sicherheit Best Practices",
		"es": "Mejores Prácticas de Seguridad de la Plataforma Aliyun",
		"fr": "Meilleures Pratiques de Sécurité de la Plateforme Aliyun",
		"pt": "Melhores Práticas de Segurança da Plataforma Aliyun"
	},
	"description": {
		"en": "Best practices for Aliyun platform security",
		"zh": "阿里云平台安全最佳实践",
		"ja": "Alibaba Cloud プラットフォームセキュリティのベストプラクティス",
		"de": "Best Practices für Alibaba Cloud Plattform-Sicherheit",
		"es": "Mejores prácticas para la seguridad de la plataforma Aliyun",
		"fr": "Meilleures pratiques pour la sécurité de la plateforme Aliyun",
		"pt": "Melhores práticas para segurança da plataforma Aliyun"
	},
	"rules": [
		"api-gateway-api-internet-request-https",
		# "cdn-domain-https-enabled",
		"ecs-disk-auto-snapshot-policy",
		"ecs-instance-enabled-security-protection",
		"ecs-instance-login-use-keypair",
		"ecs-instances-in-vpc",
		"ecs-security-group-risky-ports-check-with-protocol",
		# "mongodb-instance-backup-log-enabled",  # Commented: ROS does not support ALIYUN::MongoDB::DBInstance resource type,
		"mongodb-public-and-any-ip-access-check",
		"oss-bucket-anonymous-prohibited",
		"oss-bucket-public-read-prohibited",
		"oss-bucket-public-write-prohibited",
		"polardb-cluster-enabled-ssl",
		# "polardb-cluster-log-backup-retention",  # ROS does not support LogBackupRetentionPeriod property,
		"polardb-public-and-any-ip-access-check",
		"ram-policy-no-statements-with-admin-access-check",
		"ram-user-ak-used-expired-check",
		"ram-user-mfa-check",
		"rds-instance-enabled-log-backup",
		# "rds-instance-tls-version-check",
		"rds-public-access-check",
		"redis-instance-backup-log-enabled",
		"redis-instance-enabled-ssl",
		"redis-public-and-any-ip-access-check",
		"root-ak-check",
		"root-mfa-check",
		"slb-acl-public-access-check",
		"slb-listener-https-enabled",
		"slb-listener-risk-ports-check",
		"vpc-network-acl-risky-ports-check"
	]
}
