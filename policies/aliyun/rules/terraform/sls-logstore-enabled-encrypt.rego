package infraguard.rules.terraform.sls_logstore_enabled_encrypt

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "sls-logstore-enabled-encrypt",
	"severity": "medium",
	"name": {
		"en": "SLS Logstore Encryption Enabled",
		"zh": "SLS 日志库开启数据加密",
		"ja": "SLS ログストア暗号化が有効",
		"de": "SLS-Logstore Verschlüsselung aktiviert",
		"es": "Cifrado de Logstore SLS Habilitado",
		"fr": "Chiffrement du Logstore SLS Activé",
		"pt": "Criptografia do Logstore SLS Habilitada"
	},
	"description": {
		"en": "Ensures SLS Logstores have server-side encryption enabled.",
		"zh": "确保 SLS 日志库开启了服务端加密。",
		"ja": "SLS ログストアでサーバー側暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass SLS-Logstores serverseitige Verschlüsselung aktiviert haben.",
		"es": "Garantiza que los Logstores SLS tengan cifrado del lado del servidor habilitado.",
		"fr": "Garantit que les Logstores SLS ont le chiffrement côté serveur activé.",
		"pt": "Garante que os Logstores SLS tenham criptografia do lado do servidor habilitada."
	},
	"reason": {
		"en": "Encryption protects sensitive log data at rest.",
		"zh": "加密可以保护静态的敏感日志数据。",
		"ja": "暗号化により、保存されている機密ログデータを保護します。",
		"de": "Verschlüsselung schützt ruhende sensible Protokolldaten.",
		"es": "El cifrado protege los datos de registro sensibles en reposo.",
		"fr": "Le chiffrement protège les données de journal sensibles au repos.",
		"pt": "A criptografia protege dados de log sensíveis em repouso."
	},
	"recommendation": {
		"en": "Enable encryption for the SLS Logstore by configuring the encrypt_conf block with enable = true.",
		"zh": "通过配置 encrypt_conf 块并设置 enable = true 来为 SLS 日志库启用加密。",
		"ja": "encrypt_conf ブロックを enable = true で設定して SLS ログストアの暗号化を有効にします。",
		"de": "Aktivieren Sie die Verschlüsselung für den SLS-Logstore, indem Sie den encrypt_conf-Block mit enable = true konfigurieren.",
		"es": "Habilite el cifrado para el Logstore SLS configurando el bloque encrypt_conf con enable = true.",
		"fr": "Activez le chiffrement pour le Logstore SLS en configurant le bloc encrypt_conf avec enable = true.",
		"pt": "Habilite a criptografia para o Logstore SLS configurando o bloco encrypt_conf com enable = true."
	},
	"resource_types": ["alicloud_log_store"],
	"iac_type": "terraform"
}

is_encryption_enabled(resource) if {
	encrypt_conf := tf.get_attribute(resource, "encrypt_conf", {})
	encrypt_conf != {}
	tf.get_attribute(encrypt_conf, "enable", false) == true
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_log_store")
	not is_encryption_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_log_store.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
