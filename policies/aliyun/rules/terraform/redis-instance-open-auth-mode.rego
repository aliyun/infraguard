package infraguard.rules.terraform.redis_instance_open_auth_mode

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-instance-open-auth-mode",
	"severity": "high",
	"name": {
		"en": "Redis Authentication Mode Enabled",
		"zh": "Redis 强制开启认证模式",
		"ja": "Redis 認証モードが有効",
		"de": "Redis-Authentifizierungsmodus aktiviert",
		"es": "Modo de Autenticación Redis Habilitado",
		"fr": "Mode d'Authentification Redis Activé",
		"pt": "Modo de Autenticação Redis Habilitado"
	},
	"description": {
		"en": "Ensures Redis instances require authentication and are not in 'no-password' mode.",
		"zh": "确保 Redis 实例需要身份验证，且不处于'免密'模式。",
		"ja": "Redis インスタンスが認証を必要とし、'パスワードなし'モードではないことを確認します。",
		"de": "Stellt sicher, dass Redis-Instanzen Authentifizierung erfordern und sich nicht im 'kein Passwort'-Modus befinden.",
		"es": "Garantiza que las instancias Redis requieran autenticación y no estén en modo 'sin contraseña'.",
		"fr": "Garantit que les instances Redis nécessitent une authentification et ne sont pas en mode 'sans mot de passe'.",
		"pt": "Garante que as instâncias Redis exijam autenticação e não estejam no modo 'sem senha'."
	},
	"reason": {
		"en": "Disabling authentication allows anyone with network access to read or modify your Redis data.",
		"zh": "禁用身份验证会允许任何拥有网络访问权限的人读取或修改您的 Redis 数据。",
		"ja": "認証を無効にすると、ネットワークアクセスを持つ誰でも Redis データを読み取りまたは変更できるようになります。",
		"de": "Das Deaktivieren der Authentifizierung ermöglicht es jedem mit Netzwerkzugriff, Ihre Redis-Daten zu lesen oder zu ändern.",
		"es": "Deshabilitar la autenticación permite a cualquiera con acceso de red leer o modificar sus datos Redis.",
		"fr": "Désactiver l'authentification permet à quiconque ayant un accès réseau de lire ou modifier vos données Redis.",
		"pt": "Desabilitar a autenticação permite que qualquer pessoa com acesso à rede leia ou modifique seus dados Redis."
	},
	"recommendation": {
		"en": "Set vpc_auth_mode to \"Open\" to enable password authentication for the Redis instance.",
		"zh": "将 vpc_auth_mode 设置为 \"Open\" 为 Redis 实例启用密码身份验证。",
		"ja": "Redis インスタンスでパスワード認証を有効にするために vpc_auth_mode を \"Open\" に設定します。",
		"de": "Setzen Sie vpc_auth_mode auf \"Open\", um die Passwortauthentifizierung für die Redis-Instanz zu aktivieren.",
		"es": "Configure vpc_auth_mode como \"Open\" para habilitar la autenticación por contraseña para la instancia Redis.",
		"fr": "Définissez vpc_auth_mode sur \"Open\" pour activer l'authentification par mot de passe pour l'instance Redis.",
		"pt": "Defina vpc_auth_mode como \"Open\" para habilitar a autenticação por senha para a instância Redis."
	},
	"resource_types": ["alicloud_kvstore_instance"],
	"iac_type": "terraform"
}

is_password_free(resource) if {
	vpc_auth_mode := tf.get_attribute(resource, "vpc_auth_mode", "Open")
	vpc_auth_mode == "Close"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	is_password_free(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_kvstore_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
