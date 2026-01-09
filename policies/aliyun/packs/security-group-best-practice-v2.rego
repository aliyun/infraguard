package infraguard.packs.aliyun.security_group_best_practice_v2

import rego.v1

pack_meta := {
	"id": "security-group-best-practice-v2",
	"name": {
		"en": "Security Group Best Practice",
		"zh": "安全组最佳实践",
	},
	"description": {
		"en": "Best practices for ECS security group configuration to ensure network security and access control. Includes checks for risky ports, access restrictions, and security group settings.",
		"zh": "ECS 安全组配置最佳实践，确保网络安全和访问控制。包括危险端口检查、访问限制和安全组设置检查。",
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
