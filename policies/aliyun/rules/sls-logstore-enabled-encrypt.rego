package infraguard.rules.aliyun.sls_logstore_enabled_encrypt

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "sls-logstore-enabled-encrypt",
	"name": {
		"en": "SLS Logstore Encryption Enabled",
		"zh": "SLS 日志库开启数据加密"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures SLS Logstores have server-side encryption enabled.",
		"zh": "确保 SLS 日志库开启了服务端加密。"
	},
	"reason": {
		"en": "Encryption protects sensitive log data at rest.",
		"zh": "加密可以保护静态的敏感日志数据。"
	},
	"recommendation": {
		"en": "Enable encryption for the SLS Logstore using KMS.",
		"zh": "使用 KMS 为 SLS 日志库启用加密。"
	},
	"resource_types": ["ALIYUN::SLS::Logstore"],
}

is_compliant(resource) if {
	# Check EncryptConf
	encrypt := helpers.get_property(resource, "EncryptConf", {})
	count(encrypt) > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLS::Logstore")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EncryptConf"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
