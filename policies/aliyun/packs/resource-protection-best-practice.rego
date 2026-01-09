package infraguard.packs.aliyun.resource_protection_best_practice

import rego.v1

pack_meta := {
	"id": "resource-protection-best-practice",
	"name": {
		"en": "Resource Protection Best Practice",
		"zh": "资源开启保护最佳实践",
	},
	"description": {
		"en": "Best practices for enabling protection features on cloud resources to prevent accidental deletion or modification.",
		"zh": "为云资源开启保护功能的最佳实践,防止意外删除或修改。",
	},
	"rules": [
		# "ack-cluster-deletion-protection-enabled",
		"alb-delete-protection-enabled",
		"ecs-instance-deletion-protection-enabled",
		"ecs-instance-enabled-security-protection",
		"eip-delete-protection-enabled",
		"hbase-cluster-deletion-protection",
		"kms-key-delete-protection-enabled",
		"mongodb-instance-release-protection",
		"natgateway-delete-protection-enabled",
		"polardb-cluster-delete-protection-enabled",
		"rds-instacne-delete-protection-enabled",
		"redis-instance-release-protection",
		"slb-delete-protection-enabled",
		"slb-modify-protection-check",
		# "waf-domain-enabled-specified-protection-mode",
		# "waf-domain-enabled-specified-protection-module",
	],
}
