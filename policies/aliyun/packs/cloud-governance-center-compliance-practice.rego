package infraguard.packs.aliyun.cloud_governance_center_compliance_practice

import rego.v1

pack_meta := {
	"id": "cloud-governance-center-compliance-practice",
	"name": {
		"en": "Cloud Governance Center Compliance Practice",
		"zh": "云治理中心合规实践",
	},
	"description": {
		"en": "Compliance practices for cloud governance center",
		"zh": "云治理中心合规实践",
	},
	"rules": [
		"root-ak-check",
		"root-mfa-check",
		"ram-password-policy-check",
		"root-has-specified-role",
		"ecs-disk-encrypted",
		"ecs-instance-deletion-protection-enabled",
		# "contains-tag",  # Commented: Some resources like ACTIONTRAIL::Trail do not support Tags property
		# "required-tags",  # Commented: Some resources like ACTIONTRAIL::Trail do not support Tags property
		"ecs-security-group-risky-ports-check-with-protocol",
		"sg-public-access-check",
		"oss-bucket-server-side-encryption-enabled",
		"oss-bucket-public-write-prohibited",
		"oss-bucket-public-read-prohibited",
		"oss-bucket-logging-enabled",
		"ram-user-mfa-check",
		"ram-user-last-login-expired-check",
		"ram-user-ak-used-expired-check",
		"rds-public-access-check",
		"rds-instances-in-vpc",
		# "rds-instance-enabled-tde",
		"slb-delete-protection-enabled",
		"slb-listener-https-enabled",
		# "resource-region-limit",
	],
}
