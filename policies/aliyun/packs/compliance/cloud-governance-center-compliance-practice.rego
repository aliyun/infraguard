package infraguard.packs.aliyun.cloud_governance_center_compliance_practice

import rego.v1

pack_meta := {
	"id": "cloud-governance-center-compliance-practice",
	"name": {
		"en": "Cloud Governance Center Compliance Practice",
		"zh": "云治理中心合规实践",
		"ja": "クラウドガバナンスセンターコンプライアンス実践",
		"de": "Cloud-Governance-Center-Compliance-Praxis",
		"es": "Práctica de Cumplimiento del Centro de Gobernanza en la Nube",
		"fr": "Pratique de Conformité du Centre de Gouvernance Cloud",
		"pt": "Prática de Conformidade do Centro de Governança em Nuvem"
	},
	"description": {
		"en": "Compliance practices for cloud governance center",
		"zh": "云治理中心合规实践",
		"ja": "クラウドガバナンスセンターのコンプライアンス実践",
		"de": "Compliance-Praktiken für das Cloud-Governance-Center",
		"es": "Prácticas de cumplimiento para el centro de gobernanza en la nube",
		"fr": "Pratiques de conformité pour le centre de gouvernance cloud",
		"pt": "Práticas de conformidade para o centro de governança em nuvem"
	},
	"rules": [
		# "contains-tag",  # Commented: Some resources like ACTIONTRAIL::Trail do not support Tags property,
		"ecs-disk-encrypted",
		"ecs-instance-deletion-protection-enabled",
		"ecs-security-group-risky-ports-check-with-protocol",
		"oss-bucket-logging-enabled",
		"oss-bucket-public-read-prohibited",
		"oss-bucket-public-write-prohibited",
		"oss-bucket-server-side-encryption-enabled",
		"ram-password-policy-check",
		"ram-user-ak-used-expired-check",
		"ram-user-last-login-expired-check",
		"ram-user-mfa-check",
		# "rds-instance-enabled-tde",
		"rds-instances-in-vpc",
		"rds-public-access-check",
		# "required-tags",  # Commented: Some resources like ACTIONTRAIL::Trail do not support Tags property,
		# "resource-region-limit",
		"root-ak-check",
		"root-has-specified-role",
		"root-mfa-check",
		"sg-public-access-check",
		"slb-delete-protection-enabled",
		"slb-listener-https-enabled"
	]
}
