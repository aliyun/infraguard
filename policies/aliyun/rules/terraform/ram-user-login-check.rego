package infraguard.rules.terraform.ram_user_login_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-user-login-check",
	"severity": "medium",
	"name": {
		"en": "RAM User Login Enabled Check",
		"zh": "RAM 用户登录启用检测",
		"ja": "RAM ユーザーログイン有効化チェック",
		"de": "RAM-Benutzer Login-Aktivierungsprüfung",
		"es": "Verificación de Login de Usuario RAM Habilitado",
		"fr": "Vérification de l'Activation de la Connexion Utilisateur RAM",
		"pt": "Verificação de Login de Usuário RAM Habilitado"
	},
	"description": {
		"en": "Ensures that RAM users who do not need console access have login disabled.",
		"zh": "确保不需要控制台访问权限的 RAM 用户已禁用登录功能。",
		"ja": "コンソールアクセスが不要な RAM ユーザーのログインが無効になっていることを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer, die keinen Konsolenzugriff benötigen, Login deaktiviert haben.",
		"es": "Garantiza que los usuarios RAM que no necesitan acceso a la consola tengan el inicio de sesión deshabilitado.",
		"fr": "Garantit que les utilisateurs RAM qui n'ont pas besoin d'accès à la console ont la connexion désactivée.",
		"pt": "Garante que usuários RAM que não precisam de acesso ao console tenham login desabilitado."
	},
	"reason": {
		"en": "Disabling console login for users who only need API access reduces security risks.",
		"zh": "为仅需要 API 访问权限的用户禁用控制台登录可降低安全风险。",
		"ja": "API アクセスのみが必要なユーザーのコンソールログインを無効にすることで、セキュリティリスクを低減します。",
		"de": "Das Deaktivieren der Konsolenanmeldung für Benutzer, die nur API-Zugriff benötigen, reduziert Sicherheitsrisiken.",
		"es": "Deshabilitar el inicio de sesión en la consola para usuarios que solo necesitan acceso a la API reduce los riesgos de seguridad.",
		"fr": "Désactiver la connexion console pour les utilisateurs qui n'ont besoin que d'un accès API réduit les risques de sécurité.",
		"pt": "Desabilitar login no console para usuários que precisam apenas de acesso à API reduz riscos de segurança."
	},
	"recommendation": {
		"en": "Remove the alicloud_ram_login_profile resource to disable console login for API-only users.",
		"zh": "删除 alicloud_ram_login_profile 资源以禁用仅使用 API 的用户的控制台登录。",
		"ja": "API のみのユーザーのコンソールログインを無効にするために alicloud_ram_login_profile リソースを削除します。",
		"de": "Entfernen Sie die alicloud_ram_login_profile-Ressource, um die Konsolenanmeldung für reine API-Benutzer zu deaktivieren.",
		"es": "Elimine el recurso alicloud_ram_login_profile para deshabilitar el inicio de sesión en la consola para usuarios solo de API.",
		"fr": "Supprimez la ressource alicloud_ram_login_profile pour désactiver la connexion console pour les utilisateurs API uniquement.",
		"pt": "Remova o recurso alicloud_ram_login_profile para desabilitar login no console para usuários somente API."
	},
	"resource_types": ["alicloud_ram_login_profile"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_login_profile")
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
