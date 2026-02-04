package infraguard.rules.aliyun.sls_logstore_enabled_encrypt

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "sls-logstore-enabled-encrypt",
	"name": {
		"en": "SLS Logstore Encryption Enabled",
		"zh": "SLS 日志库开启数据加密",
		"ja": "SLS ログストア暗号化が有効",
		"de": "SLS-Logstore Verschlüsselung aktiviert",
		"es": "Cifrado de Logstore SLS Habilitado",
		"fr": "Chiffrement du Logstore SLS Activé",
		"pt": "Criptografia do Logstore SLS Habilitada",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures SLS Logstores have server-side encryption enabled.",
		"zh": "确保 SLS 日志库开启了服务端加密。",
		"ja": "SLS ログストアでサーバー側暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass SLS-Logstores serverseitige Verschlüsselung aktiviert haben.",
		"es": "Garantiza que los Logstores SLS tengan cifrado del lado del servidor habilitado.",
		"fr": "Garantit que les Logstores SLS ont le chiffrement côté serveur activé.",
		"pt": "Garante que os Logstores SLS tenham criptografia do lado do servidor habilitada.",
	},
	"reason": {
		"en": "Encryption protects sensitive log data at rest.",
		"zh": "加密可以保护静态的敏感日志数据。",
		"ja": "暗号化により、保存されている機密ログデータを保護します。",
		"de": "Verschlüsselung schützt ruhende sensible Protokolldaten.",
		"es": "El cifrado protege los datos de registro sensibles en reposo.",
		"fr": "Le chiffrement protège les données de journal sensibles au repos.",
		"pt": "A criptografia protege dados de log sensíveis em repouso.",
	},
	"recommendation": {
		"en": "Enable encryption for the SLS Logstore using KMS.",
		"zh": "使用 KMS 为 SLS 日志库启用加密。",
		"ja": "KMS を使用して SLS ログストアの暗号化を有効にします。",
		"de": "Aktivieren Sie die Verschlüsselung für den SLS-Logstore mit KMS.",
		"es": "Habilite el cifrado para el Logstore SLS usando KMS.",
		"fr": "Activez le chiffrement pour le Logstore SLS en utilisant KMS.",
		"pt": "Habilite a criptografia para o Logstore SLS usando KMS.",
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
