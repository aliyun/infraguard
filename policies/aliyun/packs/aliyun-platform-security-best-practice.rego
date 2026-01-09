package infraguard.packs.aliyun.aliyun_platform_security_best_practice

import rego.v1

pack_meta := {
	"id": "aliyun-platform-security-best-practice",
	"name": {
		"en": "Aliyun Platform Security Best Practice",
		"zh": "阿里云平台安全最佳实践",
	},
	"description": {
		"en": "Best practices for Aliyun platform security",
		"zh": "阿里云平台安全最佳实践",
	},
	"rules": [
		"root-mfa-check",
		"root-ak-check",
		"api-gateway-api-internet-request-https",
		# "cdn-domain-https-enabled",
		"ecs-disk-auto-snapshot-policy",
		"ecs-instance-enabled-security-protection",
		"ecs-instances-in-vpc",
		"ecs-instance-login-use-keypair",
		"ecs-security-group-risky-ports-check-with-protocol",
		"mongodb-public-and-any-ip-access-check",
		# "mongodb-instance-backup-log-enabled",  # Commented: ROS does not support ALIYUN::MongoDB::DBInstance resource type
		"oss-bucket-public-write-prohibited",
		"oss-bucket-public-read-prohibited",
		"oss-bucket-anonymous-prohibited",
		"polardb-public-and-any-ip-access-check",
		"polardb-cluster-enabled-ssl",
		# "polardb-cluster-log-backup-retention",  # ROS does not support LogBackupRetentionPeriod property
		"ram-policy-no-statements-with-admin-access-check",
		"ram-user-mfa-check",
		"ram-user-ak-used-expired-check",
		"rds-public-access-check",
		"rds-instance-enabled-log-backup",
		# "rds-instance-tls-version-check",
		"redis-public-and-any-ip-access-check",
		"redis-instance-enabled-ssl",
		"redis-instance-backup-log-enabled",
		"slb-acl-public-access-check",
		"slb-listener-risk-ports-check",
		"slb-listener-https-enabled",
		"vpc-network-acl-risky-ports-check",
	],
}
