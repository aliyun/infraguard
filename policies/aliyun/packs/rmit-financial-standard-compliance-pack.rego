package infraguard.packs.aliyun.rmit_financial_standard_compliance_pack

import rego.v1

pack_meta := {
	"id": "rmit-financial-standard-compliance-pack",
	"name": {
		"en": "RMiT Financial Standard Compliance Pack",
		"zh": "RMiT 金融标准检查合规包",
		"ja": "RMiT 金融標準コンプライアンスパック",
		"de": "RMiT Finanzstandard-Compliance-Paket",
		"es": "Paquete de Cumplimiento del Estándar Financiero RMiT",
		"fr": "Pack de Conformité à la Norme Financière RMiT",
		"pt": "Pacote de Conformidade com Padrão Financeiro RMiT"
	},
	"description": {
		"en": "Compliance pack for RMiT financial standards",
		"zh": "RMiT 金融标准检查合规包",
		"ja": "RMiT 金融標準のコンプライアンスパック",
		"de": "Compliance-Paket für RMiT-Finanzstandards",
		"es": "Paquete de cumplimiento para estándares financieros RMiT",
		"fr": "Pack de conformité pour les normes financières RMiT",
		"pt": "Pacote de conformidade para padrões financeiros RMiT"
	},
	"rules": [
		"actiontrail-enabled",
		"actiontrail-trail-intact-enabled",
		"ecs-disk-auto-snapshot-policy",
		"ecs-disk-encrypted",
		# "ecs-instance-no-public-ip",
		"ecs-instances-in-vpc",
		# "elasticsearch-instance-in-vpc",  # Commented: ROS ALIYUN::ElasticSearch::Instance requires VSwitchId (all instances are in VPC),
		"kms-key-rotation-enabled",
		"oss-bucket-anonymous-prohibited",
		"oss-bucket-logging-enabled",
		"oss-bucket-only-https-enabled",
		"oss-bucket-server-side-encryption-enabled",
		"oss-bucket-versioning-enabled",
		"oss-default-encryption-kms",
		"oss-encryption-byok-check",
		"ram-group-has-member-check",
		"ram-password-policy-check",
		"ram-policy-no-statements-with-admin-access-check",
		"ram-user-group-membership-check",
		"ram-user-last-login-expired-check",
		"ram-user-mfa-check",
		"ram-user-no-policy-check",
		# "rds-instance-enabled-tde",
		"rds-multi-az-support",
		"rds-public-access-check",
		"root-ak-check",
		"sg-public-access-check",
		"slb-delete-protection-enabled",
		"slb-listener-https-enabled",
		# "slb-server-certificate-expired",
		"vpc-flow-logs-enabled",
		# "vpn-ipsec-connection-status-check",
		"waf-instance-logging-enabled"
	]
}
