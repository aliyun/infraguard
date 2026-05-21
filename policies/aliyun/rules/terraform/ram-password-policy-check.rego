package infraguard.rules.terraform.ram_password_policy_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-password-policy-check",
	"severity": "medium",
	"name": {
		"en": "RAM Password Policy Check",
		"zh": "RAM 密码策略检测",
		"ja": "RAM パスワードポリシーチェック",
		"de": "RAM-Passwortrichtlinien-Prüfung",
		"es": "Verificación de Política de Contraseña RAM",
		"fr": "Vérification de la Politique de Mot de Passe RAM",
		"pt": "Verificação de Política de Senha RAM"
	},
	"description": {
		"en": "Ensures that the RAM password policy meets the specified security requirements.",
		"zh": "确保 RAM 密码策略符合指定的安全要求。",
		"ja": "RAM パスワードポリシーが指定されたセキュリティ要件を満たしていることを確認します。",
		"de": "Stellt sicher, dass die RAM-Passwortrichtlinie die festgelegten Sicherheitsanforderungen erfüllt.",
		"es": "Garantiza que la política de contraseña RAM cumpla con los requisitos de seguridad especificados.",
		"fr": "Garantit que la politique de mot de passe RAM répond aux exigences de sécurité spécifiées.",
		"pt": "Garante que a política de senha RAM atenda aos requisitos de segurança especificados."
	},
	"reason": {
		"en": "Strong password policies help prevent unauthorized access to accounts.",
		"zh": "强密码策略有助于防止对账号的未经授权访问。",
		"ja": "強力なパスワードポリシーは、アカウントへの不正アクセスを防ぐのに役立ちます。",
		"de": "Starke Passwortrichtlinien helfen, unbefugten Zugriff auf Konten zu verhindern.",
		"es": "Las políticas de contraseña fuertes ayudan a prevenir el acceso no autorizado a las cuentas.",
		"fr": "Des politiques de mot de passe fortes aident à prévenir l'accès non autorisé aux comptes.",
		"pt": "Políticas de senha fortes ajudam a prevenir acesso não autorizado a contas."
	},
	"recommendation": {
		"en": "Set minimum_password_length to at least 8 in the alicloud_ram_account_password_policy resource.",
		"zh": "在 alicloud_ram_account_password_policy 资源中将 minimum_password_length 设置为至少 8。",
		"ja": "alicloud_ram_account_password_policy リソースで minimum_password_length を 8 以上に設定します。",
		"de": "Setzen Sie minimum_password_length auf mindestens 8 in der alicloud_ram_account_password_policy-Ressource.",
		"es": "Establezca minimum_password_length en al menos 8 en el recurso alicloud_ram_account_password_policy.",
		"fr": "Définissez minimum_password_length à au moins 8 dans la ressource alicloud_ram_account_password_policy.",
		"pt": "Defina minimum_password_length para pelo menos 8 no recurso alicloud_ram_account_password_policy."
	},
	"resource_types": ["alicloud_ram_account_password_policy"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_account_password_policy")
	min_len := tf.get_attribute(resource, "minimum_password_length", 0)
	not min_len >= 8
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_account_password_policy.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
