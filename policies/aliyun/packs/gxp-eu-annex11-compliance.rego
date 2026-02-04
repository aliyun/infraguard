package infraguard.packs.aliyun.gxp_eu_annex11_compliance

import rego.v1

pack_meta := {
	"id": "gxp-eu-annex11-compliance",
	"name": {
		"en": "GxP EU Annex 11 Compliance",
		"zh": "GxP 欧盟附录 11 标准合规包",
		"ja": "GxP EU 附属書 11 コンプライアンス",
		"de": "GxP EU Anhang 11 Compliance",
		"es": "Cumplimiento del Anexo 11 GxP de la UE",
		"fr": "Conformité à l'Annexe 11 GxP de l'UE",
		"pt": "Conformidade com o Anexo 11 GxP da UE",
	},
	"description": {
		"en": "Compliance pack for pharmaceutical, biotechnology and medical device companies using cloud services that need to meet GxP EU Annex 11 standards. This pack provides mappings between standard requirements and Alibaba Cloud product settings.",
		"zh": "在制药、生物技术和医疗器械领域中使用计算机化系统的企业和组织，在用云过程需要满足 GxP 欧盟标准。本合规包模板提供了标准细则与阿里云的产品设置的对应关系。",
		"ja": "GxP EU 附属書 11 基準を満たす必要があるクラウドサービスを使用する製薬、バイオテクノロジー、医療機器企業向けのコンプライアンスパック。このパックは、標準要件と Alibaba Cloud 製品設定の間のマッピングを提供します。",
		"de": "Compliance-Paket für pharmazeutische, biotechnologische und Medizinprodukteunternehmen, die Cloud-Dienste nutzen und die GxP EU Anhang 11-Standards erfüllen müssen. Dieses Paket bietet Zuordnungen zwischen Standardanforderungen und Alibaba Cloud Produkteinstellungen.",
		"es": "Paquete de cumplimiento para empresas farmacéuticas, biotecnológicas y de dispositivos médicos que utilizan servicios en la nube y necesitan cumplir con los estándares del Anexo 11 GxP de la UE. Este paquete proporciona mapeos entre los requisitos estándar y la configuración de productos de Alibaba Cloud.",
		"fr": "Pack de conformité pour les entreprises pharmaceutiques, biotechnologiques et de dispositifs médicaux utilisant des services cloud qui doivent répondre aux normes de l'Annexe 11 GxP de l'UE. Ce pack fournit des correspondances entre les exigences standard et les paramètres des produits Alibaba Cloud.",
		"pt": "Pacote de conformidade para empresas farmacêuticas, de biotecnologia e de dispositivos médicos que usam serviços em nuvem e precisam atender aos padrões do Anexo 11 GxP da UE. Este pacote fornece mapeamentos entre os requisitos padrão e as configurações de produtos do Alibaba Cloud.",
	},
	"rules": [
		"ack-cluster-rrsa-enabled",
		# "adb-cluster-log-backup-enabled",
		# "adb-cluster-audit-log-enabled",  # Commented: ROS ADB::DBCluster does not support AuditLog property
		"alb-instance-multi-zone",
		"alb-server-group-multi-zone",
		"api-gateway-api-internet-request-https",
		# "cdn-domain-tls13-enabled",
		# "dts-instance-sync-job-ssl-enabled",
		# "dts-instance-migration-job-ssl-enabled",
		"ecs-snapshot-retention-days",
		"ecs-in-use-disk-encrypted",
		"ecs-disk-auto-snapshot-policy",
		"ecs-instance-enabled-security-protection",
		"ecs-instance-deletion-protection-enabled",
		# "ecs-instance-monitor-enabled",  # Commented: ROS ECS::Instance does not support CloudMonitorFlags property
		# "ecs-instance-updated-security-vul",  # Commented: ROS ECS::Instance does not support Vulnerabilities property
		# "ecs-instance-status-no-stopped",  # Commented: ROS ECS::Instance does not support Status property
		"ecs-instance-ram-role-attached",
		# "ecs-security-group-not-used",  # Commented: ROS ECS::SecurityGroup does not support Used property
		"eip-attached",
		"ess-scaling-group-attach-multi-switch",
		# "elasticsearch-instance-used-https-protocol",  # Commented: ROS ALIYUN::ElasticSearch::Instance does not support Protocol property
		"elasticsearch-instance-enabled-data-node-encryption",
		# "elasticsearch-instance-snapshot-enabled",  # Commented: ROS does not support AutoSnapshot property for ALIYUN::ElasticSearch::Instance
		"fc-function-custom-domain-and-tls-enable",
		"fc-service-bind-role",
		"hbase-cluster-deletion-protection",
		"mse-cluster-config-auth-enabled",
		"mongodb-instance-release-protection",
		"mongodb-instance-multi-zone",
		# "mongodb-instance-backup-log-enabled",  # Commented: ROS does not support ALIYUN::MongoDB::DBInstance resource type
		"mongodb-instance-log-audit",
		# "nas-filesystem-enable-backup-plan",
		"oss-zrs-enabled",
		"oss-bucket-public-write-prohibited",
		"oss-bucket-policy-no-any-anonymous",
		"oss-bucket-versioning-enabled",
		"oss-bucket-logging-enabled",
		# "oceanbase-instance-enabled-backup",  # Commented: ROS does not support ALIYUN::OceanBase::DBInstance resource type
		# "polardb-cluster-log-backup-retention",  # ROS does not support LogBackupRetentionPeriod property
		"polardb-cluster-enabled-ssl",
		"polardb-cluster-enabled-tde",
		"polardb-cluster-delete-protection-enabled",
		"polardb-cluster-multi-zone",
		"privatelink-servier-endpoint-multi-zone",
		"ram-user-mfa-check",
		"ram-user-ak-create-date-expired-check",
		"ram-user-last-login-expired-check",
		"ram-user-login-check",
		"ram-user-ak-used-expired-check",
		"rds-instance-enabled-log-backup",
		"rds-multi-az-support",
		"rds-instance-enabled-ssl",
		# "rds-instance-enabled-tde",
		"rds-instacne-delete-protection-enabled",
		# "rds-instance-sql-collector-retention",  # Commented: ROS RDS::DBInstance does not support SQLCollectorRetention property
		"redis-instance-multi-zone",
		"redis-instance-enabled-ssl",
		"redis-instance-enabled-byok-tde",
		"redis-instance-release-protection",
		"redis-instance-backup-log-enabled",
		# "redis-instance-enabled-audit-log",  # Commented: ROS ALIYUN::REDIS::Instance does not support AuditLogConfig property
		"slb-delete-protection-enabled",
		"slb-instance-multi-zone",
		"slb-instance-log-enabled",
		"slb-vserver-group-multi-zone",
		"sls-logstore-enabled-encrypt",
		# "vpn-ipsec-connection-encrypt-enable",
		"waf-instance-logging-enabled",
	],
}
