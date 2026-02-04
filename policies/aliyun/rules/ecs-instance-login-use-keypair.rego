package infraguard.rules.aliyun.ecs_instance_login_use_keypair

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ecs-instance-login-use-keypair",
	"name": {
		"en": "ECS Instance Login Using Key Pair",
		"zh": "ECS 实例登录使用密钥对",
		"ja": "ECS インスタンスのログインにキーペアを使用",
		"de": "ECS-Instanz-Anmeldung mit Schlüsselpaar",
		"es": "Inicio de Sesión de Instancia ECS Usando Par de Claves",
		"fr": "Connexion d'Instance ECS Utilisant une Paire de Clés",
		"pt": "Login de Instância ECS Usando Par de Chaves",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that ECS instances use key pairs for login instead of passwords.",
		"zh": "确保 ECS 实例使用密钥对进行登录，而不是密码。",
		"ja": "ECS インスタンスがパスワードではなくキーペアを使用してログインすることを確認します。",
		"de": "Stellt sicher, dass ECS-Instanzen Schlüsselpaare für die Anmeldung verwenden, anstatt Passwörter.",
		"es": "Garantiza que las instancias ECS usen pares de claves para iniciar sesión en lugar de contraseñas.",
		"fr": "Garantit que les instances ECS utilisent des paires de clés pour la connexion au lieu de mots de passe.",
		"pt": "Garante que as instâncias ECS usem pares de chaves para login em vez de senhas.",
	},
	"reason": {
		"en": "Key pair login is more secure than password login.",
		"zh": "密钥对登录比密码登录更安全。",
		"ja": "キーペアログインはパスワードログインよりも安全です。",
		"de": "Die Anmeldung mit Schlüsselpaar ist sicherer als die Anmeldung mit Passwort.",
		"es": "El inicio de sesión con par de claves es más seguro que el inicio de sesión con contraseña.",
		"fr": "La connexion avec paire de clés est plus sécurisée que la connexion avec mot de passe.",
		"pt": "Login com par de chaves é mais seguro que login com senha.",
	},
	"recommendation": {
		"en": "Configure key pair login for the ECS instance and disable password login.",
		"zh": "为 ECS 实例配置密钥对登录，并禁用密码登录。",
		"ja": "ECS インスタンスでキーペアログインを設定し、パスワードログインを無効にします。",
		"de": "Konfigurieren Sie die Anmeldung mit Schlüsselpaar für die ECS-Instanz und deaktivieren Sie die Anmeldung mit Passwort.",
		"es": "Configure el inicio de sesión con par de claves para la instancia ECS y deshabilite el inicio de sesión con contraseña.",
		"fr": "Configurez la connexion avec paire de clés pour l'instance ECS et désactivez la connexion avec mot de passe.",
		"pt": "Configure login com par de chaves para a instância ECS e desabilite login com senha.",
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])
	not helpers.has_property(resource, "KeyPairName")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "KeyPairName"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
