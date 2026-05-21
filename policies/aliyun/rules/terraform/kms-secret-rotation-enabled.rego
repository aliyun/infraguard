package infraguard.rules.terraform.kms_secret_rotation_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "kms-secret-rotation-enabled",
	"severity": "medium",
	"name": {
		"en": "KMS Secret Automatic Rotation Enabled",
		"zh": "KMS 凭据开启自动轮转",
		"ja": "KMS シークレットの自動ローテーションが有効",
		"de": "KMS-Geheimnis automatische Rotation aktiviert",
		"es": "Rotación automática de secreto KMS habilitada",
		"fr": "Rotation automatique de secret KMS activée",
		"pt": "Rotação automática de segredo KMS habilitada"
	},
	"description": {
		"en": "Ensures that KMS secrets have automatic rotation enabled to enhance security by periodically rotating secret values.",
		"zh": "确保 KMS 凭据开启了自动轮转，通过定期轮转凭据值来增强安全性。",
		"ja": "KMS シークレットで自動ローテーションが有効になっている場合、準拠と見なされます。汎用シークレットは適用されません。",
		"de": "KMS-Geheimnis hat automatische Rotation aktiviert, wird als konform betrachtet. Generische Geheimnisse sind nicht anwendbar.",
		"es": "El secreto KMS tiene rotación automática habilitada, considerado conforme. Los secretos genéricos no son aplicables.",
		"fr": "Le secret KMS a la rotation automatique activée, considéré comme conforme. Les secrets génériques ne sont pas applicables.",
		"pt": "Segredo KMS tem rotação automática habilitada, considerado conforme. Segredos genéricos não são aplicáveis."
	},
	"reason": {
		"en": "The KMS secret does not have automatic rotation enabled, which may increase the risk of credential compromise over time.",
		"zh": "KMS 凭据未开启自动轮转，随着时间推移可能增加凭据泄露的风险。",
		"ja": "KMS シークレットで自動ローテーションが有効になっていません",
		"de": "KMS-Geheimnis hat keine automatische Rotation aktiviert",
		"es": "El secreto KMS no tiene rotación automática habilitada",
		"fr": "Le secret KMS n'a pas la rotation automatique activée",
		"pt": "Segredo KMS não tem rotação automática habilitada"
	},
	"recommendation": {
		"en": "Enable automatic rotation for the KMS secret by setting enable_automatic_rotation to true.",
		"zh": "通过将 enable_automatic_rotation 设置为 true 来为 KMS 凭据开启自动轮转。",
		"ja": "認証情報を定期的にローテーションしてセキュリティを強化するために、KMS シークレットで自動ローテーションを有効にします",
		"de": "Aktivieren Sie die automatische Rotation für KMS-Geheimnisse, um die Sicherheit durch regelmäßige Rotation von Anmeldeinformationen zu verbessern",
		"es": "Habilite la rotación automática para el secreto KMS para mejorar la seguridad rotando credenciales regularmente",
		"fr": "Activez la rotation automatique pour le secret KMS pour améliorer la sécurité en faisant tourner régulièrement les identifiants",
		"pt": "Habilite rotação automática para segredo KMS para melhorar a segurança rotacionando credenciais regularmente"
	},
	"resource_types": ["alicloud_kms_secret"],
	"iac_type": "terraform"
}

is_compliant(resource) if {
	tf.get_attribute(resource, "enable_automatic_rotation", false) == true
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kms_secret")
	not is_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_kms_secret.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
