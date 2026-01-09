package infraguard.packs.aliyun.change_management_best_practice

import rego.v1

pack_meta := {
	"id": "change-management-best-practice",
	"name": {
		"en": "Change Management Best Practice",
		"zh": "变更管理最佳实践",
	},
	"description": {
		"en": "From the change management dimension, detect the stability of cloud resources to help identify potential issues in advance and improve stability and operational efficiency.",
		"zh": "从变更管理维度,对云上资源的稳定性做检测,有助于提前发现隐患,提升稳定性和运维效率。",
	},
	"rules": [
		# "adb-cluster-maintain-time-check",  # Commented: ROS ADB::DBCluster does not support MaintainTime property
		"ecs-snapshot-policy-timepoints-check",
		"ecs-snapshot-retention-days",
		"polardb-cluster-maintain-time-check",
		"rds-instance-maintain-time-check",
		"redis-instance-backup-time-check",
	],
}
