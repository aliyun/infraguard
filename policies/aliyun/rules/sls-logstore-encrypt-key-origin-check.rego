package infraguard.rules.aliyun.sls_logstore_encrypt_key_origin_check

import data.infraguard.helpers
import rego.v1

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
		"en": "Configure the Logstore to use BYOK encryption with externally imported key material.",
		"zh": "配置日志库使用 BYOK 加密，导入外部密钥材料。",
		"ja": "外部からインポートされたキー材料で BYOK 暗号化を使用するようにログストアを設定します。",
		"de": "Konfigurieren Sie den Logstore, um BYOK-Verschlüsselung mit extern importiertem Schlüsselmaterial zu verwenden.",
		"es": "Configure el Logstore para usar cifrado BYOK con material de clave importado externamente.",
		"fr": "Configurez le Logstore pour utiliser le chiffrement BYOK avec du matériel de clé importé externe.",
		"pt": "Configure o Logstore para usar criptografia BYOK com material de chave importado externamente."
	},
	"resource_types": ["ALIYUN::SLS::Logstore"]
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
