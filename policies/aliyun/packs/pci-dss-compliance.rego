package infraguard.packs.aliyun.pci_dss_compliance

import rego.v1

pack_meta := {
	"id": "pci-dss-compliance",
	"name": {
		"en": "PCI-DSS Data Security Standard Compliance",
		"zh": "PCI-DSS 数据安全标准合规包",
	},
	"description": {
		"en": "Compliance pack for Payment Card Industry Data Security Standard (PCI-DSS). This pack helps organizations verify their cloud resources meet PCI-DSS requirements for protecting cardholder data.",
		"zh": "支付卡行业数据安全标准(PCI-DSS)合规包。本合规包帮助组织验证其云资源是否符合 PCI-DSS 保护持卡人数据的要求。",
	},
	"rules": [
		"api-gateway-api-internet-request-https",
		# "api-gateway-group-domain-access-waf",
		# "cdn-domain-https-enabled",
		"ecs-snapshot-retention-days",
		"ecs-disk-encrypted",
		"ecs-instance-enabled-security-protection",
		# "ecs-instance-monitor-enabled",  # Commented: ROS ECS::Instance does not support CloudMonitorFlags property
		# "ecs-instance-no-public-ip",
		# "ecs-instance-updated-security-vul",  # Commented: ROS ECS::Instance does not support Vulnerabilities property
		# "ecs-instance-os-name-check",
		"sg-public-access-check",
		"ecs-security-group-risky-ports-check-with-protocol",
		"ecs-security-group-white-list-port-check",
		# "elasticsearch-instance-used-https-protocol",  # Commented: ROS ALIYUN::ElasticSearch::Instance does not support Protocol property
		"fc-function-custom-domain-and-tls-enable",
		"kms-key-rotation-enabled",
		"kms-key-delete-protection-enabled",
		"kms-secret-rotation-enabled",
		# "nas-filesystem-enable-backup-plan",
		"oss-bucket-anonymous-prohibited",
		"oss-zrs-enabled",
		"oss-bucket-server-side-encryption-enabled",
		"oss-encryption-byok-check",
		"oss-bucket-only-https-enabled",
		"polardb-public-and-any-ip-access-check",
		# "polardb-cluster-default-time-zone-not-system",
		# "polardb-cluster-level-one-backup-retention",
		"polardb-cluster-enabled-tde",
		"polardb-cluster-maintain-time-check",
		# "polardb-cluster-enabled-auditing",  # ROS does not support SQLCollectorStatus property
		# "polardb-cluster-log-backup-retention",  # ROS does not support LogBackupRetentionPeriod property
		"ram-group-has-member-check",
		"ram-policy-no-statements-with-admin-access-check",
		# "ram-policy-in-use-check",
		"ram-user-ak-create-date-expired-check",
		"ram-user-mfa-check",
		# "ram-user-no-has-specified-policy",
		"ram-user-last-login-expired-check",
		"ram-user-group-membership-check",
		"ram-user-login-check",
		"ram-user-ak-used-expired-check",
		"rds-public-connection-and-any-ip-access-check",
		"rds-instance-enabled-log-backup",
		"rds-instance-enabled-auditing",
		# "rds-instance-sql-collector-retention",  # Commented: ROS RDS::DBInstance does not support SQLCollectorRetention property
		# "rds-instance-enabled-byok-tde",
		"rds-instance-maintain-time-check",
		"rds-instance-enabled-disk-encryption",
		# "redis-instance-enabled-tde",
		"slb-all-listenter-tls-policy-check",
		"sls-logstore-enabled-encrypt",
		"vpc-flow-logs-enabled",
		# "waf-domain-enabled-specified-protection-module",
		"waf-instance-logging-enabled",
	],
}
