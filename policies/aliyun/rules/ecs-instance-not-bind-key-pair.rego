package infraguard.rules.aliyun.ecs_instance_not_bind_key_pair

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ecs-instance-not-bind-key-pair",
	"name": {
		"en": "ECS Instance Not Bound to Key Pair",
		"zh": "ECS 实例未绑定密钥对检测",
		"ja": "ECS インスタンスがキーペアにバインドされていない",
		"de": "ECS-Instanz nicht an Schlüsselpaar gebunden",
		"es": "Instancia ECS No Vinculada a Par de Claves",
		"fr": "Instance ECS Non Liée à une Paire de Clés",
		"pt": "Instância ECS Não Vinculada a Par de Chaves",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that ECS instances use key pairs for authentication instead of passwords.",
		"zh": "确保 ECS 实例使用密钥对进行身份验证，而不是密码。",
		"ja": "ECS インスタンスがパスワードではなくキーペアを使用して認証することを確認します。",
		"de": "Stellt sicher, dass ECS-Instanzen Schlüsselpaare für die Authentifizierung verwenden, anstatt Passwörter.",
		"es": "Garantiza que las instancias ECS usen pares de claves para autenticación en lugar de contraseñas.",
		"fr": "Garantit que les instances ECS utilisent des paires de clés pour l'authentification au lieu de mots de passe.",
		"pt": "Garante que as instâncias ECS usem pares de chaves para autenticação em vez de senhas.",
	},
	"reason": {
		"en": "Key pair authentication is more secure than password authentication.",
		"zh": "密钥对身份验证比密码身份验证更安全。",
		"ja": "キーペア認証はパスワード認証よりも安全です。",
		"de": "Die Authentifizierung mit Schlüsselpaar ist sicherer als die Authentifizierung mit Passwort.",
		"es": "La autenticación con par de claves es más segura que la autenticación con contraseña.",
		"fr": "L'authentification par paire de clés est plus sécurisée que l'authentification par mot de passe.",
		"pt": "Autenticação com par de chaves é mais segura que autenticação com senha.",
	},
	"recommendation": {
		"en": "Bind a key pair to the ECS instance and disable password authentication.",
		"zh": "为 ECS 实例绑定密钥对，并禁用密码身份验证。",
		"ja": "ECS インスタンスにキーペアをバインドし、パスワード認証を無効にします。",
		"de": "Binden Sie ein Schlüsselpaar an die ECS-Instanz und deaktivieren Sie die Passwortauthentifizierung.",
		"es": "Vincule un par de claves a la instancia ECS y deshabilite la autenticación por contraseña.",
		"fr": "Lieez une paire de clés à l'instance ECS et désactivez l'authentification par mot de passe.",
		"pt": "Vincule um par de chaves à instância ECS e desabilite autenticação com senha.",
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
