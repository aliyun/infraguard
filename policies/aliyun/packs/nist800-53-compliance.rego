package infraguard.packs.aliyun.nist800_53_compliance

import rego.v1

pack_meta := {
	"id": "nist800-53-compliance",
	"name": {
		"en": "NIST 800-53 Compliance",
		"zh": "NIST800-53 合规包",
		"ja": "NIST 800-53 コンプライアンス",
		"de": "NIST 800-53 Compliance",
		"es": "Cumplimiento NIST 800-53",
		"fr": "Conformité NIST 800-53",
		"pt": "Conformidade NIST 800-53",
	},
	"description": {
		"en": "Compliance pack for NIST 800-53 Security and Privacy Controls. This pack helps organizations verify their cloud resources meet NIST 800-53 security control requirements.",
		"zh": "NIST 800-53 安全与隐私控制合规包。本合规包帮助组织验证其云资源是否符合 NIST 800-53 安全控制要求。",
		"ja": "NIST 800-53 セキュリティおよびプライバシー制御のコンプライアンスパック。このパックは、組織がクラウドリソースが NIST 800-53 セキュリティ制御要件を満たしていることを確認するのに役立ちます。",
		"de": "Compliance-Paket für NIST 800-53 Sicherheits- und Datenschutzkontrollen. Dieses Paket hilft Organisationen zu überprüfen, ob ihre Cloud-Ressourcen die NIST 800-53 Sicherheitskontrollanforderungen erfüllen.",
		"es": "Paquete de cumplimiento para los Controles de Seguridad y Privacidad NIST 800-53. Este paquete ayuda a las organizaciones a verificar que sus recursos en la nube cumplan con los requisitos de control de seguridad NIST 800-53.",
		"fr": "Pack de conformité pour les Contrôles de Sécurité et de Confidentialité NIST 800-53. Ce pack aide les organisations à vérifier que leurs ressources cloud répondent aux exigences de contrôle de sécurité NIST 800-53.",
		"pt": "Pacote de conformidade para Controles de Segurança e Privacidade NIST 800-53. Este pacote ajuda as organizações a verificar se seus recursos em nuvem atendem aos requisitos de controle de segurança NIST 800-53.",
	},
	"rules": [
		"ack-cluster-public-endpoint-check",
		"ack-cluster-encryption-enabled",
		"ack-cluster-supported-version",
		"ack-cluster-upgrade-latest-version",
		# "ack-cluster-control-plane-log-enable",
		# "adb-public-access-check",  # Commented: ROS ADB::DBCluster does not support PublicEndpoint property
		# "adb-cluster-audit-log-enabled",  # Commented: ROS ADB::DBCluster does not support AuditLog property
		# "adb-cluster-log-backup-enabled",
		# "adb-cluster-maintain-time-check",  # Commented: ROS ADB::DBCluster does not support MaintainTime property
		"alb-instance-multi-zone",
		# "api-gateway-group-domain-access-waf-or-waf3",  # Commented: ROS ApiGateway::Group does not support PassthroughWaf property
		"api-gateway-group-enabled-ssl",
		# "api-gateway-group-log-enabled",
		# "api-group-custom-trace-enabled",
		# "cdn-domain-https-enabled",
		# "cdn-domain-tls13-enabled",
		# "cr-repository-image-scanning-enabled",
		"cr-repository-immutablity-enable",
		"firewall-asset-open-protect",
		# "dts-instance-migration-job-ssl-enabled",
		# "eci-containergroup-environment-no-specified-keys",
		"ecs-in-use-disk-encrypted",
		"ecs-disk-auto-snapshot-policy",
		# "ecs-disk-in-use",
		# "ecs-instance-monitor-enabled",  # Commented: ROS ECS::Instance does not support CloudMonitorFlags property
		# "ecs-instance-meta-data-mode-check",
		# "ecs-instance-status-no-stopped",  # Commented: ROS ECS::Instance does not support Status property
		# "ecs-instance-updated-security-vul",  # Commented: ROS ECS::Instance does not support Vulnerabilities property
		"ecs-instance-not-bind-key-pair",
		"ecs-instance-ram-role-attached",
		"ecs-security-group-white-list-port-check",
		# "ecs-security-group-not-used",  # Commented: ROS ECS::SecurityGroup does not support Used property
		"eip-attached",
		"ess-scaling-configuration-enabled-internet-check",
		# "ess-group-health-check",
		"ess-scaling-group-attach-multi-switch",
		"elasticsearch-public-and-any-ip-access-check",
		"elasticsearch-instance-enabled-data-node-encryption",
		# "elasticsearch-instance-used-https-protocol",  # Commented: ROS ALIYUN::ElasticSearch::Instance does not support Protocol property
		# "fc-function-settings-check",
		"fc-service-vpc-binding",
		"fc-service-internet-access-disable",
		# "fc-service-log-enable",
		# "kms-key-origin-not-external",  # Commented: ROS KMS::Key does not support Origin property
		# "kms-key-state-not-pending-deletion",  # Commented: ROS KMS::Key does not support KeyState property (runtime state only)
		# "kms-secret-last-rotation-date-check",
		"kms-secret-rotation-enabled",
		# "mongodb-instance-backup-log-enabled",  # Commented: ROS does not support ALIYUN::MongoDB::DBInstance resource type
		"mongodb-instance-log-audit",
		# "nas-filesystem-access-point-enabled-ram",  # Commented: ROS does not support ALIYUN::NAS::AccessPoint resource type
		# "nas-filesystem-enable-backup-plan",
		# "nas-filesystem-access-point-root-directory-check",  # Commented: ROS does not support ALIYUN::NAS::AccessPoint resource type
		"nas-filesystem-encrypt-type-check",
		"oss-bucket-policy-no-any-anonymous",
		"oss-bucket-public-read-prohibited",
		"oss-bucket-public-write-prohibited",
		"oss-bucket-server-side-encryption-enabled",
		"oss-zrs-enabled",
		"oss-bucket-logging-enabled",
		"oss-bucket-versioning-enabled",
		"oss-default-encryption-kms",
		"oss-bucket-only-https-enabled",
		# "ots-instance-all-table-encrypted",  # ROS template does not support SSESpecification property
		# "polardb-cluster-enabled-auditing",  # ROS does not support SQLCollectorStatus property
		# "polardb-cluster-level-one-backup-retention",
		"polardb-cluster-multi-zone",
		# "polardb-dbversion-status-check",
		"ram-group-has-member-check",
		# "ram-group-in-use-check",
		"ram-policy-no-statements-with-admin-access-check",
		# "ram-policy-in-use-check",
		"ram-user-mfa-check",
		"rds-instance-enabled-log-backup",
		"rds-multi-az-support",
		"rds-public-connection-and-any-ip-access-check",
		# "rds-instance-sql-collector-retention",  # Commented: ROS RDS::DBInstance does not support SQLCollectorRetention property
		"rds-instance-enabled-disk-encryption",
		# "rds-instance-enabled-tde",
		# "redis-instance-upgrade-latest-version",
		"redis-instance-backup-log-enabled",
		"slb-all-listener-servers-multi-zone",
		"slb-all-listenter-tls-policy-check",
		"slb-listener-https-enabled",
		"slb-instance-log-enabled",
		# "ssl-certificate-expired-check",
		"vpc-network-acl-risky-ports-check",
		# "vpc-network-acl-unused-check",
		# "vpc-routetable-destination-cidr-check",  # ROS does not support ALIYUN::VPC::RouteEntry resource type
		"vpc-flow-logs-enabled",
		# "vpn-ipsec-connection-status-check",
		# "waf3-instance-enabled-specified-defense-rules",
	],
}
