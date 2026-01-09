package infraguard.packs.aliyun.quick_start_compliance_pack

import rego.v1

pack_meta := {
	"id": "quick-start-compliance-pack",
	"name": {
		"en": "Quick Start Compliance Pack",
		"zh": "快速体验合规包",
	},
	"description": {
		"en": "A quick start compliance pack covering basic security best practices for ECS, OSS, RAM, and RDS.",
		"zh": "快速体验合规包,涵盖 ECS、OSS、RAM 和 RDS 的基本安全最佳实践。",
	},
	"rules": [
		# "ecs-instance-no-public-ip",
		"oss-bucket-public-read-prohibited",
		"ram-policy-no-statements-with-admin-access-check",
		# "ram-user-mfa-check-v2",
		# "ram-user-ak-create-date-expired-check-v2",
		"ram-user-activated-ak-quantity-check",
		"rds-public-connection-and-any-ip-access-check",
	],
}
