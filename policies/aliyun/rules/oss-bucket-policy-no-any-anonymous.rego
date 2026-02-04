package infraguard.rules.aliyun.oss_bucket_policy_no_any_anonymous

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "oss-bucket-policy-no-any-anonymous",
	"severity": "high",
	"name": {
		"en": "OSS bucket policy does not grant permissions to anonymous users",
		"zh": "OSS 存储空间不能为匿名账号授予任何权限",
		"ja": "OSS バケットポリシーが匿名ユーザーに権限を付与していない",
		"de": "OSS-Bucket-Richtlinie gewährt anonymen Benutzern keine Berechtigungen",
		"es": "La política de bucket OSS no otorga permisos a usuarios anónimos",
		"fr": "La politique de bucket OSS n'accorde pas de permissions aux utilisateurs anonymes",
		"pt": "A política de bucket OSS não concede permissões a usuários anônimos"
	},
	"description": {
		"en": "OSS bucket policy does not grant any read or write permissions to anonymous users.",
		"zh": "OSS Bucket 授权策略中未授予匿名账号任何读写权限。",
		"ja": "OSS バケットポリシーは匿名ユーザーに読み取りまたは書き込み権限を付与していません。",
		"de": "OSS-Bucket-Richtlinie gewährt anonymen Benutzern keine Lese- oder Schreibberechtigungen.",
		"es": "La política de bucket OSS no otorga permisos de lectura o escritura a usuarios anónimos.",
		"fr": "La politique de bucket OSS n'accorde pas de permissions de lecture ou d'écriture aux utilisateurs anonymes.",
		"pt": "A política de bucket OSS não concede permissões de leitura ou gravação a usuários anônimos."
	},
	"reason": {
		"en": "OSS bucket policy grants permissions to anonymous users, which may expose sensitive data.",
		"zh": "OSS Bucket 授权策略授予匿名账号权限,可能导致敏感数据泄露。",
		"ja": "OSS バケットポリシーが匿名ユーザーに権限を付与しているため、機密データが公開される可能性があります。",
		"de": "OSS-Bucket-Richtlinie gewährt anonymen Benutzern Berechtigungen, was sensible Daten preisgeben kann.",
		"es": "La política de bucket OSS otorga permisos a usuarios anónimos, lo que puede exponer datos sensibles.",
		"fr": "La politique de bucket OSS accorde des permissions aux utilisateurs anonymes, ce qui peut exposer des données sensibles.",
		"pt": "A política de bucket OSS concede permissões a usuários anônimos, o que pode expor dados sensíveis."
	},
	"recommendation": {
		"en": "Remove anonymous user permissions from OSS bucket policy. Ensure Principal does not contain '*' for anonymous access.",
		"zh": "从 OSS Bucket 授权策略中移除匿名用户权限。确保 Principal 不包含'*'以避免匿名访问。",
		"ja": "OSS バケットポリシーから匿名ユーザーの権限を削除します。匿名アクセスを避けるために、Principal に '*' が含まれていないことを確認します。",
		"de": "Entfernen Sie anonyme Benutzerberechtigungen aus der OSS-Bucket-Richtlinie. Stellen Sie sicher, dass Principal kein '*' für anonymen Zugriff enthält.",
		"es": "Elimine los permisos de usuario anónimo de la política de bucket OSS. Asegúrese de que Principal no contenga '*' para acceso anónimo.",
		"fr": "Supprimez les permissions des utilisateurs anonymes de la politique de bucket OSS. Assurez-vous que Principal ne contient pas '*' pour l'accès anonyme.",
		"pt": "Remova permissões de usuários anônimos da política de bucket OSS. Certifique-se de que Principal não contenha '*' para acesso anônimo."
	},
	"resource_types": ["ALIYUN::OSS::Bucket"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")

	# Check if bucket has a policy
	policy := helpers.get_property(resource, "Policy", {})

	# If no policy is set, it's compliant (no anonymous access granted)
	count(policy) > 0

	# Check if policy contains statements
	statement := policy.Statement[_]

	# Check if statement grants access to anonymous users (Principal: "*")
	principal := object.get(statement, "Principal", "")
	principal == "*"
	statement.Effect == "Allow"

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Policy", "Statement"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
