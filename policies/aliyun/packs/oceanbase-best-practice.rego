package infraguard.packs.aliyun.oceanbase_best_practice

import rego.v1

pack_meta := {
	"id": "oceanbase-best-practice",
	"name": {
		"en": "OceanBase Best Practice",
		"zh": "OceanBase 最佳实践",
	},
	"description": {
		"en": "Continuously check OceanBase compliance based on security practices.",
		"zh": "基于安全实践持续检查 OceanBase 的合规性。",
	},
	"rules": [],
	# "oceanbase-instance-enabled-backup",  # Commented: ROS does not support ALIYUN::OceanBase::DBInstance resource type
	# "oceanbase-instance-enabled-ssl",
	# "oceanbase-instance-enabled-sql-diagnosis",
	# "oceanbase-tenant-security-ip-check",
	# "oceanbase-tenant-enabled-encryption",

}
