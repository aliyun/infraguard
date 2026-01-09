package infraguard.packs.aliyun.ros_best_practice

import rego.v1

pack_meta := {
	"id": "ros-best-practice",
	"name": {
		"en": "ROS Best Practice Pack",
		"zh": "ROS 最佳实践合规包",
	},
	"description": {
		"en": "A compliance pack covering ROS template best practices, including metadata configuration and sensitive parameter protection.",
		"zh": "涵盖 ROS 模板最佳实践的合规包，包括元数据配置和敏感参数保护等。",
	},
	"rules": [
		"metadata-ros-composer-check",
		"parameter-sensitive-noecho-check",
	],
}
