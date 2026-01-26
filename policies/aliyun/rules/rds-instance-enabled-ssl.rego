package infraguard.rules.aliyun.rds_instance_enabled_ssl

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rds-instance-enabled-ssl",
	"name": {
		"en": "RDS Instance SSL Enabled",
		"zh": "RDS 实例开启 SSL 加密"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures RDS instances have SSL encryption enabled.",
		"zh": "确保 RDS 实例开启了 SSL 加密。"
	},
	"reason": {
		"en": "SSL encryption protects data in transit from eavesdropping and tampering.",
		"zh": "SSL 加密可保护传输中的数据免受窃听和篡改。"
	},
	"recommendation": {
		"en": "Enable SSL for the RDS instance.",
		"zh": "为 RDS 实例开启 SSL 加密。"
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

is_compliant(resource) if {
	ssl := helpers.get_property(resource, "SSLSetting", "Disabled")
	ssl != "Disabled"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SSLSetting"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
