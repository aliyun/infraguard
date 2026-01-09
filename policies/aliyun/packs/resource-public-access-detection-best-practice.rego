package infraguard.packs.aliyun.resource_public_access_detection_best_practice

import rego.v1

pack_meta := {
	"id": "resource-public-access-detection-best-practice",
	"name": {
		"en": "Resource Public Access Detection Best Practice",
		"zh": "资源开启公网检测最佳实践",
	},
	"description": {
		"en": "Best practices for detecting and managing public access to cloud resources to ensure security.",
		"zh": "检测和管理云资源公网访问的最佳实践,确保安全性。",
	},
	"rules": [
		"ack-cluster-public-endpoint-check",
		# "adb-public-access-check",  # Commented: ROS ADB::DBCluster does not support PublicEndpoint property
		# "kafka-instance-public-access-check",
		# "apigateway-ipv4-public-access-check",
		# "apigateway-ipv6-public-access-check",
		# "cr-instance-public-access-check",  # Commented: ROS CR::Instance does not support PublicNetworkAccess property
		"cr-repository-type-private",
		"ecs-running-instance-no-public-ip",
		"sg-public-access-check",
		"emr-cluster-master-public-access-check",
		"elasticsearch-public-and-any-ip-access-check",
		# "hbase-public-access-check",
		# "lindorm-instance-public-access-check",
		"mse-cluster-config-auth-enabled",
		"mongodb-public-and-any-ip-access-check",
		# "nas-access-group-public-access-check",
		# "ots-instance-network-not-normal",
		# "oceanbase-public-and-any-ip-access-check",
		"polardb-public-and-any-ip-access-check",
		"rds-public-access-check",
		"redis-public-and-any-ip-access-check",
		# "tsdb-instance-public-access-check",
	],
}
