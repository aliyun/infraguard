package infraguard.rules.terraform.ram_user_last_login_expired_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-user-last-login-expired-check",
	"severity": "low",
	"name": {
		"en": "RAM User Last Login Check",
		"zh": "RAM 用户最后登录时间核查",
		"ja": "RAM ユーザー最終ログインチェック",
		"de": "RAM-Benutzer letzte Anmeldung-Prüfung",
		"es": "Verificación de Último Inicio de Sesión de Usuario RAM",
		"fr": "Vérification de la Dernière Connexion d'Utilisateur RAM",
		"pt": "Verificação de Último Login de Usuário RAM"
	},
	"description": {
		"en": "Checks if RAM users are properly configured with a display_name set.",
		"zh": "检查 RAM 用户是否正确配置了 display_name。",
		"ja": "RAM ユーザーに display_name が適切に設定されているかチェックします。",
		"de": "Prüft, ob RAM-Benutzer ordnungsgemäß mit einem display_name konfiguriert sind.",
		"es": "Verifica si los usuarios RAM están correctamente configurados con display_name establecido.",
		"fr": "Vérifie si les utilisateurs RAM sont correctement configurés avec un display_name défini.",
		"pt": "Verifica se usuários RAM estão corretamente configurados com display_name definido."
	},
	"reason": {
		"en": "Inactive users should be removed to reduce security surface.",
		"zh": "不活跃的用户应予以移除以减少安全暴露面。",
		"ja": "非アクティブなユーザーは、セキュリティ面を減らすために削除する必要があります。",
		"de": "Inaktive Benutzer sollten entfernt werden, um die Sicherheitsfläche zu reduzieren.",
		"es": "Los usuarios inactivos deben eliminarse para reducir la superficie de seguridad.",
		"fr": "Les utilisateurs inactifs doivent être supprimés pour réduire la surface de sécurité.",
		"pt": "Usuários inativos devem ser removidos para reduzir a superfície de segurança."
	},
	"recommendation": {
		"en": "Set display_name on the alicloud_ram_user resource to ensure proper user governance.",
		"zh": "在 alicloud_ram_user 资源上设置 display_name 以确保正确的用户治理。",
		"ja": "適切なユーザーガバナンスを確保するために、alicloud_ram_user リソースに display_name を設定します。",
		"de": "Setzen Sie display_name auf die alicloud_ram_user-Ressource, um eine ordnungsgemäße Benutzerverwaltung zu gewährleisten.",
		"es": "Establezca display_name en el recurso alicloud_ram_user para garantizar una gobernanza adecuada del usuario.",
		"fr": "Définissez display_name sur la ressource alicloud_ram_user pour assurer une bonne gouvernance des utilisateurs.",
		"pt": "Defina display_name no recurso alicloud_ram_user para garantir a governança adequada do usuário."
	},
	"resource_types": ["alicloud_ram_user"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_user")
	display_name := tf.get_attribute(resource, "display_name", "")
	display_name == ""
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_user.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
