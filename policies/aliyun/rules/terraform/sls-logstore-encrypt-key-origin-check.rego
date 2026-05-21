package infraguard.rules.terraform.sls_logstore_encrypt_key_origin_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "sls-logstore-encrypt-key-origin-check",
	"severity": "medium",
	"name": {
		"en": "SLS Logstore Encryption Key Origin Check",
		"zh": "日志服务日志库加密使用的主密钥材料来源为用户自行导入",
		"ja": "SLS ログストア暗号化キーオリジンチェック",
		"de": "SLS-Logstore Verschlüsselungsschlüssel-Herkunftsprüfung",
		"es": "Verificación de Origen de Clave de Cifrado de Logstore SLS",
		"fr": "Vérification de l'Origine de la Clé de Chiffrement du Logstore SLS",
		"pt": "Verificação de Origem da Chave de Criptografia do Logstore SLS"
	},
	"description": {
		"en": "Ensures SLS Logstores use externally imported key material (BYOK) for encryption, which provides better control over encryption keys.",
		"zh": "确保 SLS 日志库使用外部导入的密钥材料（BYOK）进行加密，以更好地控制加密密钥。",
		"ja": "SLS ログストアが暗号化に外部からインポートされたキー材料（BYOK）を使用していることを確認します。これにより、暗号化キーをより適切に制御できます。",
		"de": "Stellt sicher, dass SLS-Logstores extern importiertes Schlüsselmaterial (BYOK) für die Verschlüsselung verwenden, was eine bessere Kontrolle über Verschlüsselungsschlüssel bietet.",
		"es": "Garantiza que los Logstores SLS usen material de clave importado externamente (BYOK) para el cifrado, lo que proporciona un mejor control sobre las claves de cifrado.",
		"fr": "Garantit que les Logstores SLS utilisent du matériel de clé importé externe (BYOK) pour le chiffrement, ce qui offre un meilleur contrôle sur les clés de chiffrement.",
		"pt": "Garante que os Logstores SLS usem material de chave importado externamente (BYOK) para criptografia, o que fornece melhor controle sobre as chaves de criptografia."
	},
	"reason": {
		"en": "Using externally imported key material provides better control over encryption keys and enhances security posture.",
		"zh": "使用外部导入的密钥材料可以更好地控制加密密钥并增强安全性。",
		"ja": "外部からインポートされたキー材料を使用することで、暗号化キーをより適切に制御し、セキュリティ体制を強化できます。",
		"de": "Die Verwendung extern importierten Schlüsselmaterials bietet eine bessere Kontrolle über Verschlüsselungsschlüssel und verbessert die Sicherheitslage.",
		"es": "Usar material de clave importado externamente proporciona un mejor control sobre las claves de cifrado y mejora la postura de seguridad.",
		"fr": "L'utilisation de matériel de clé importé externe offre un meilleur contrôle sur les clés de chiffrement et améliore la posture de sécurité.",
		"pt": "Usar material de chave importado externamente fornece melhor controle sobre as chaves de criptografia e melhora a postura de segurança."
	},
	"recommendation": {
		"en": "Configure the Logstore encrypt_conf with user_cmk_info block containing a valid cmk_key_id for BYOK encryption.",
		"zh": "配置 Logstore 的 encrypt_conf，在 user_cmk_info 块中包含有效的 cmk_key_id 以实现 BYOK 加密。",
		"ja": "BYOK 暗号化のために有効な cmk_key_id を含む user_cmk_info ブロックで Logstore の encrypt_conf を設定します。",
		"de": "Konfigurieren Sie encrypt_conf des Logstores mit einem user_cmk_info-Block, der eine gültige cmk_key_id für BYOK-Verschlüsselung enthält.",
		"es": "Configure encrypt_conf del Logstore con un bloque user_cmk_info que contenga un cmk_key_id válido para cifrado BYOK.",
		"fr": "Configurez encrypt_conf du Logstore avec un bloc user_cmk_info contenant un cmk_key_id valide pour le chiffrement BYOK.",
		"pt": "Configure encrypt_conf do Logstore com um bloco user_cmk_info contendo um cmk_key_id válido para criptografia BYOK."
	},
	"resource_types": ["alicloud_log_store"],
	"iac_type": "terraform"
}

has_byok_encryption(resource) if {
	encrypt_conf := tf.get_attribute(resource, "encrypt_conf", {})
	encrypt_conf != {}
	tf.get_attribute(encrypt_conf, "enable", false) == true
	user_cmk_info := tf.get_attribute(encrypt_conf, "user_cmk_info", {})
	user_cmk_info != {}
	cmk_key_id := tf.get_attribute(user_cmk_info, "cmk_key_id", "")
	cmk_key_id != ""
	not tf.is_unknown(cmk_key_id)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_log_store")
	not has_byok_encryption(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_log_store.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
