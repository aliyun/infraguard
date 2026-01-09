package infraguard.packs.aliyun.aliyun_well_architected_security_pillar_best_practice

import rego.v1

pack_meta := {
	"id": "aliyun-well-architected-security-pillar-best-practice",
	"name": {
		"en": "Aliyun Well-Architected Security Pillar Best Practice",
		"zh": "阿里云卓越架构安全支柱最佳实践",
	},
	"description": {
		"en": "Best practices for Aliyun well-architected security pillar",
		"zh": "阿里云卓越架构安全支柱最佳实践",
	},
	"rules": [
		"actiontrail-trail-intact-enabled",
		"ram-password-policy-check",
		"root-ak-check",
		"root-mfa-check",
		"security-center-version-check",
		# "adb-public-access-check",  # Commented: ROS ADB::DBCluster does not support PublicEndpoint property
		# "adb-cluster-maintain-time-check",  # Commented: ROS ADB::DBCluster does not support MaintainTime property
		# "api-gateway-group-domain-access-waf-or-waf3",  # Commented: ROS ApiGateway::Group does not support PassthroughWaf property
		"api-gateway-group-enabled-ssl",
		"ecs-disk-idle-check",
		"ecs-in-use-disk-encrypted",
		"ecs-instance-enabled-security-protection",
		# "ecs-instance-status-no-stopped",  # Commented: ROS ECS::Instance does not support Status property
		# "ecs-instance-updated-security-vul",  # Commented: ROS ECS::Instance does not support Vulnerabilities property
		"ecs-instances-in-vpc",
		"ecs-running-instance-no-public-ip",
		"ecs-instance-ram-role-attached",
		"ecs-security-group-risky-ports-check-with-protocol",
		"ecs-security-group-white-list-port-check",
		# "ecs-security-group-not-used",  # Commented: ROS ECS::SecurityGroup does not support Used property
		"ess-scaling-configuration-enabled-internet-check",
		"elasticsearch-instance-enabled-data-node-encryption",
		# "elasticsearch-instance-in-vpc",  # Commented: ROS ALIYUN::ElasticSearch::Instance requires VSwitchId (all instances are in VPC)
		"fc-service-vpc-binding",
		"fc-service-internet-access-disable",
		# "kms-key-origin-not-external",  # Commented: ROS KMS::Key does not support Origin property
		"kms-key-rotation-enabled",
		# "kms-key-state-not-pending-deletion",  # Commented: ROS KMS::Key does not support KeyState property (runtime state only)
		"kms-secret-rotation-enabled",
		"nas-filesystem-encrypt-type-check",
		"oss-bucket-policy-no-any-anonymous",
		"oss-bucket-public-read-prohibited",
		"oss-bucket-public-write-prohibited",
		"oss-bucket-server-side-encryption-enabled",
		"oss-bucket-logging-enabled",
		"oss-bucket-versioning-enabled",
		"oss-encryption-byok-check",
		"oss-bucket-only-https-enabled",
		# "ots-instance-all-table-encrypted",  # ROS template does not support SSESpecification property
		"ram-group-has-member-check",
		"ram-policy-no-statements-with-admin-access-check",
		"ram-user-ak-create-date-expired-check",
		"ram-user-mfa-check",
		"ram-user-no-product-admin-access",
		"ram-user-ak-used-expired-check",
		"ram-user-group-membership-check",
		"rds-public-connection-and-any-ip-access-check",
		# "rds-instance-enabled-tde",
		# "rds-instance-sql-collector-retention",  # Commented: ROS RDS::DBInstance does not support SQLCollectorRetention property
		"slb-listener-https-enabled",
		"slb-instance-log-enabled",
		"vpc-flow-logs-enabled",
		"waf-instance-logging-enabled",
	],
}
