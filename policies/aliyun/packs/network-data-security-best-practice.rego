# Network and Data Security Best Practice Pack
# Best practices for network and data security including encryption, access control, and secure configurations.
package infraguard.packs.aliyun.network_data_security_best_practice

import rego.v1

# Pack metadata with i18n support
pack_meta := {
	"id": "network-data-security-best-practice",
	"name": {
		"en": "Network and Data Security Best Practice",
		"zh": "网络及数据安全最佳实践",
	},
	"description": {
		"en": "Best practices for network and data security including ECS instance security, OSS bucket encryption and access control, RDS instance security configurations.",
		"zh": "网络及数据安全最佳实践，包括 ECS 实例安全、OSS 存储空间加密和访问控制、RDS 实例安全配置。",
	},
	"rules": [
		"ecs-in-use-disk-encrypted",
		"ecs-instances-in-vpc",
		"oss-bucket-server-side-encryption-enabled",
		"oss-bucket-public-write-prohibited",
		"oss-bucket-public-read-prohibited",
		"oss-bucket-logging-enabled",
		"oss-encryption-byok-check",
		"rds-public-access-check",
	],
}
