package infraguard.rules.aliyun.sls_logstore_encrypt_key_origin_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:sls-logstore-encrypt-key-origin-check",
	"name": {
		"en": "SLS Logstore Encryption Key Origin Check",
		"zh": "日志服务日志库加密使用的主密钥材料来源为用户自行导入"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures SLS Logstores use externally imported key material (BYOK) for encryption, which provides better control over encryption keys.",
		"zh": "确保 SLS 日志库使用外部导入的密钥材料（BYOK）进行加密，以更好地控制加密密钥。"
	},
	"reason": {
		"en": "Using externally imported key material provides better control over encryption keys and enhances security posture.",
		"zh": "使用外部导入的密钥材料可以更好地控制加密密钥并增强安全性。"
	},
	"recommendation": {
		"en": "Configure the Logstore to use BYOK encryption with externally imported key material.",
		"zh": "配置日志库使用 BYOK 加密，导入外部密钥材料。"
	},
	"resource_types": ["ALIYUN::SLS::Logstore"],
}

# Check if encryption is enabled with BYOK (externally imported key)
is_compliant(resource) if {
	# Direct access to nested properties
	encrypt := resource.Properties.EncryptConf
	encrypt != null
	encrypt.Enable == true

	# Check for BYOK configuration - UserCmkInfo with CmkKeyId indicates BYOK
	user_cmk := encrypt.UserCmkInfo
	user_cmk != null
	user_cmk.CmkKeyId != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLS::Logstore")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EncryptConf", "UserCmkInfo"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
