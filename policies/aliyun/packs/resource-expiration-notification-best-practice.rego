package infraguard.packs.aliyun.resource_expiration_notification_best_practice

import rego.v1

pack_meta := {
	"id": "resource-expiration-notification-best-practice",
	"name": {
		"en": "Resource Expiration Notification Best Practice",
		"zh": "资源到期提醒最佳实践",
	},
	"description": {
		"en": "Detects stability risks related to resource expiration, helping to discover hidden dangers in advance and improve stability and operational efficiency.",
		"zh": "从到期风险维度，对云上资源的稳定性做检测，有助于提前发现隐患，提升稳定性和运维效率。",
	},
	"rules": [
		# "adb-cluster-expired-check",
		"bastionhost-instance-expired-check",
		# "polardb-x1-instance-expired-check",
		# "polardb-x2-instance-expired-check",
		"ecs-instance-expired-check",
		# "eip-address-expired-check",
		"hbase-cluster-expired-check",
		"mongodb-cluster-expired-check",
		"polardb-cluster-expired-check",
		"rds-instance-expired-check",
		"redis-instance-expired-check",
		# "slb-instance-expired-check",
	],
}
