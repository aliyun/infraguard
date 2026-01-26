package infraguard.rules.aliyun.mongodb_instance_enabled_ssl

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "mongodb-instance-enabled-ssl",
	"name": {
		"en": "MongoDB Instance SSL Enabled",
		"zh": "MongoDB 实例开启 SSL 加密"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures MongoDB instances have SSL encryption enabled.",
		"zh": "确保 MongoDB 实例开启了 SSL 加密。"
	},
	"reason": {
		"en": "SSL protects data in transit between the client and the database.",
		"zh": "SSL 保护客户端与数据库之间传输的数据。"
	},
	"recommendation": {
		"en": "Enable SSL for the MongoDB instance.",
		"zh": "为 MongoDB 实例开启 SSL 加密。"
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

is_compliant(resource) if {
	ssl_options := helpers.get_property(resource, "SSLOptions", {})
	action := object.get(ssl_options, "SSLAction", "Close")
	action == "Open"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MONGODB::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SSLOptions", "SSLAction"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
