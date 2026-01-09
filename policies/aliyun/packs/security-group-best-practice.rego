# Security Group Best Practice Pack
# A collection of rules for checking security group compliance to reduce security risks.
package infraguard.packs.aliyun.security_group_best_practice

import rego.v1

# Pack metadata with i18n support
pack_meta := {
	"id": "security-group-best-practice",
	"name": {
		"en": "Security Group Best Practice",
		"zh": "安全组最佳实践",
	},
	"description": {
		"en": "Continuously check security group rules for compliance to reduce security risks.",
		"zh": "持续检查安全组规则的合规性，降低安全风险。",
	},
	"rules": [
		"ecs-instance-attached-security-group",
		"ecs-security-group-white-list-port-check",
		"sg-public-access-check",
		"ecs-security-group-not-open-all-port",
		"ecs-security-group-not-open-all-protocol",
		"ecs-security-group-not-internet-cidr-access",
		"ecs-security-group-egress-not-all-access",
		"ecs-security-group-risky-ports-check-with-protocol",
	],
}
