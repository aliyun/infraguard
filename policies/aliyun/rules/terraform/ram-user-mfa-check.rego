package infraguard.rules.terraform.ram_user_mfa_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-user-mfa-check",
	"severity": "high",
	"name": {
		"en": "RAM User MFA Enabled",
		"zh": "RAM 用户开启 MFA",
		"ja": "RAM ユーザーで MFA が有効",
		"de": "RAM-Benutzer MFA aktiviert",
		"es": "MFA de Usuario RAM Habilitado",
		"fr": "MFA Utilisateur RAM Activé",
		"pt": "MFA de Usuário RAM Habilitado"
	},
	"description": {
		"en": "RAM users with console access should have multi-factor authentication (MFA) enabled.",
		"zh": "检测 RAM 用户是否开通 MFA 二次验证登录，开通视为合规。",
		"ja": "コンソールアクセスを持つ RAM ユーザーは、多要素認証（MFA）を有効にする必要があります。",
		"de": "RAM-Benutzer mit Konsolenzugriff sollten Multi-Faktor-Authentifizierung (MFA) aktiviert haben.",
		"es": "Los usuarios RAM con acceso a la consola deben tener habilitada la autenticación multifactor (MFA).",
		"fr": "Les utilisateurs RAM avec accès à la console doivent avoir l'authentification multifacteur (MFA) activée.",
		"pt": "Usuários RAM com acesso ao console devem ter autenticação multifator (MFA) habilitada."
	},
	"reason": {
		"en": "RAM users without MFA are vulnerable to password compromise, posing a significant security risk.",
		"zh": "RAM 用户未开启 MFA，一旦密码泄露，账号将面临极大的安全风险。",
		"ja": "MFA がない RAM ユーザーはパスワードの侵害に対して脆弱で、重大なセキュリティリスクをもたらします。",
		"de": "RAM-Benutzer ohne MFA sind anfällig für Passwortkompromittierung und stellen ein erhebliches Sicherheitsrisiko dar.",
		"es": "Los usuarios RAM sin MFA son vulnerables al compromiso de contraseñas, lo que plantea un riesgo de seguridad significativo.",
		"fr": "Les utilisateurs RAM sans MFA sont vulnérables au compromis de mot de passe, ce qui pose un risque de sécurité important.",
		"pt": "Usuários RAM sem MFA são vulneráveis a comprometimento de senha, representando um risco significativo de segurança."
	},
	"recommendation": {
		"en": "Set mfa_bind_required to true on the alicloud_ram_login_profile resource.",
		"zh": "在 alicloud_ram_login_profile 资源上将 mfa_bind_required 设置为 true。",
		"ja": "alicloud_ram_login_profile リソースで mfa_bind_required を true に設定します。",
		"de": "Setzen Sie mfa_bind_required auf true in der alicloud_ram_login_profile-Ressource.",
		"es": "Establezca mfa_bind_required en true en el recurso alicloud_ram_login_profile.",
		"fr": "Définissez mfa_bind_required sur true dans la ressource alicloud_ram_login_profile.",
		"pt": "Defina mfa_bind_required como true no recurso alicloud_ram_login_profile."
	},
	"resource_types": ["alicloud_ram_login_profile"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_login_profile")
	mfa := tf.get_attribute(resource, "mfa_bind_required", false)
	mfa != true
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_login_profile.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
