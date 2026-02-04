package infraguard.rules.aliyun.eci_containergroup_environment_no_specified_keys

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "eci-containergroup-environment-no-specified-keys",
	"name": {
		"en": "ECI Container Group Does Not Contain Sensitive Environment Variables",
		"zh": "ECI 容器组不包含敏感环境变量",
		"ja": "ECI コンテナグループに機密環境変数が含まれていない",
		"de": "ECI-Containergruppe enthält keine sensiblen Umgebungsvariablen",
		"es": "El Grupo de Contenedores ECI No Contiene Variables de Entorno Sensibles",
		"fr": "Le Groupe de Conteneurs ECI Ne Contient Pas de Variables d'Environnement Sensibles",
		"pt": "Grupo de Contêineres ECI Não Contém Variáveis de Ambiente Sensíveis",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that ECI container groups do not have sensitive environment variables like passwords or access keys.",
		"zh": "ECI 容器组不包含敏感环境变量（如密码、AccessKey 等），视为合规。",
		"ja": "ECI コンテナグループにパスワードやアクセスキーなどの機密環境変数がないことを確認します。",
		"de": "Stellt sicher, dass ECI-Containergruppen keine sensiblen Umgebungsvariablen wie Passwörter oder Zugriffsschlüssel haben.",
		"es": "Garantiza que los grupos de contenedores ECI no tengan variables de entorno sensibles como contraseñas o claves de acceso.",
		"fr": "Garantit que les groupes de conteneurs ECI n'ont pas de variables d'environnement sensibles comme les mots de passe ou les clés d'accès.",
		"pt": "Garante que os grupos de contêineres ECI não tenham variáveis de ambiente sensíveis como senhas ou chaves de acesso.",
	},
	"reason": {
		"en": "ECI container group contains sensitive environment variables, which may leak credentials.",
		"zh": "ECI 容器组包含敏感环境变量，可能导致凭证泄露。",
		"ja": "ECI コンテナグループに機密環境変数が含まれており、認証情報が漏洩する可能性があります。",
		"de": "ECI-Containergruppe enthält sensible Umgebungsvariablen, die zu Anmeldedatenlecks führen können.",
		"es": "El grupo de contenedores ECI contiene variables de entorno sensibles, lo que puede provocar la filtración de credenciales.",
		"fr": "Le groupe de conteneurs ECI contient des variables d'environnement sensibles, ce qui peut entraîner une fuite d'identifiants.",
		"pt": "O grupo de contêineres ECI contém variáveis de ambiente sensíveis, o que pode causar vazamento de credenciais.",
	},
	"recommendation": {
		"en": "Use Secrets or parameter store to manage sensitive environment variables.",
		"zh": "请使用 Secret 或参数存储来管理敏感环境变量。",
		"ja": "機密環境変数を管理するには、Secrets またはパラメータストアを使用します。",
		"de": "Verwenden Sie Secrets oder Parameter Store, um sensible Umgebungsvariablen zu verwalten.",
		"es": "Use Secrets o almacén de parámetros para gestionar variables de entorno sensibles.",
		"fr": "Utilisez Secrets ou le magasin de paramètres pour gérer les variables d'environnement sensibles.",
		"pt": "Use Secrets ou armazenamento de parâmetros para gerenciar variáveis de ambiente sensíveis.",
	},
	"resource_types": ["ALIYUN::ECI::ContainerGroup"],
}

# Default sensitive environment variable keys
default sensitive_keys := [
	"password",
	"passwd",
	"pwd",
	"secret",
	"key",
	"token",
	"credential",
	"access_key",
	"accesskey",
	"secret_key",
	"secretkey",
	"access_key_id",
]

# Get sensitive keys from parameters or use default
get_sensitive_keys := input.rule_parameters.sensitive_env_keys if {
	count(input.rule_parameters.sensitive_env_keys) > 0
} else := sensitive_keys

# Check if a key is sensitive (supports partial match)
is_sensitive_key(key) if {
	some sensitive in get_sensitive_keys
	contains(lower(key), lower(sensitive))
}

# Check if environment variable contains sensitive key
has_sensitive_env(container) if {
	some env in container.EnvironmentVar
	is_sensitive_key(env.Key)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECI::ContainerGroup")

	some container in resource.Properties.Container
	has_sensitive_env(container)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Container", "EnvironmentVar"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
