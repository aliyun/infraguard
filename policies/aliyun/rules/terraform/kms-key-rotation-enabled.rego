package infraguard.rules.terraform.kms_key_rotation_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "kms-key-rotation-enabled",
	"severity": "medium",
	"name": {
		"en": "KMS Key Automatic Rotation Enabled",
		"zh": "KMS 密钥开启自动轮转",
		"ja": "KMS キーの自動ローテーションが有効",
		"de": "KMS-Schlüssel automatische Rotation aktiviert",
		"es": "Rotación automática de clave KMS habilitada",
		"fr": "Rotation automatique de clé KMS activée",
		"pt": "Rotação automática de chave KMS habilitada"
	},
	"description": {
		"en": "Ensures that KMS keys have automatic rotation enabled to enhance security by periodically rotating key material.",
		"zh": "确保 KMS 密钥开启了自动轮转，通过定期轮转密钥材料来增强安全性。",
		"ja": "KMS ユーザーマスターキーで自動ローテーションが有効になっている場合、準拠と見なされます。サービスキーと外部からインポートされたキーは適用されません。",
		"de": "KMS-Benutzer-Hauptschlüssel hat automatische Rotation aktiviert, wird als konform betrachtet. Dienstschlüssel und extern importierte Schlüssel sind nicht anwendbar.",
		"es": "La clave maestra de usuario KMS tiene rotación automática habilitada, considerada conforme. Las claves de servicio y las claves importadas externamente no son aplicables.",
		"fr": "La clé maître utilisateur KMS a la rotation automatique activée, considérée comme conforme. Les clés de service et les clés importées externement ne sont pas applicables.",
		"pt": "Chave mestra de usuário KMS tem rotação automática habilitada, considerada conforme. Chaves de serviço e chaves importadas externamente não são aplicáveis."
	},
	"reason": {
		"en": "The KMS key does not have automatic rotation enabled, which may increase the risk of key compromise over time.",
		"zh": "KMS 密钥未开启自动轮转，随着时间推移可能增加密钥泄露的风险。",
		"ja": "KMS キーで自動ローテーションが有効になっていません",
		"de": "KMS-Schlüssel hat keine automatische Rotation aktiviert",
		"es": "La clave KMS no tiene rotación automática habilitada",
		"fr": "La clé KMS n'a pas la rotation automatique activée",
		"pt": "Chave KMS não tem rotação automática habilitada"
	},
	"recommendation": {
		"en": "Enable automatic rotation for the KMS key by setting automatic_rotation to \"Enabled\".",
		"zh": "通过将 automatic_rotation 设置为 \"Enabled\" 来为 KMS 密钥开启自动轮转。",
		"ja": "暗号化キーを定期的にローテーションしてセキュリティを強化するために、KMS キーで自動ローテーションを有効にします",
		"de": "Aktivieren Sie die automatische Rotation für KMS-Schlüssel, um die Sicherheit durch regelmäßige Rotation von Verschlüsselungsschlüsseln zu verbessern",
		"es": "Habilite la rotación automática para la clave KMS para mejorar la seguridad rotando claves de cifrado regularmente",
		"fr": "Activez la rotation automatique pour la clé KMS pour améliorer la sécurité en faisant tourner régulièrement les clés de chiffrement",
		"pt": "Habilite rotação automática para chave KMS para melhorar a segurança rotacionando chaves de criptografia regularmente"
	},
	"resource_types": ["alicloud_kms_key"],
	"iac_type": "terraform"
}

is_compliant(resource) if {
	tf.get_attribute(resource, "automatic_rotation", "Disabled") == "Enabled"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kms_key")
	not is_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_kms_key.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
