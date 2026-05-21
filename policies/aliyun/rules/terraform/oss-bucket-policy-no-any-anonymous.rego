package infraguard.rules.terraform.oss_bucket_policy_no_any_anonymous

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-bucket-policy-no-any-anonymous",
	"severity": "high",
	"name": {
		"en": "OSS Bucket Policy No Anonymous Access",
		"zh": "OSS 存储空间不能为匿名账号授予任何权限",
		"ja": "OSS バケットポリシーが匿名ユーザーに権限を付与していない",
		"de": "OSS-Bucket-Richtlinie gewährt anonymen Benutzern keine Berechtigungen",
		"es": "La política de bucket OSS no otorga permisos a usuarios anónimos",
		"fr": "La politique de bucket OSS n'accorde pas de permissions aux utilisateurs anonymes",
		"pt": "A política de bucket OSS não concede permissões a usuários anônimos"
	},
	"description": {
		"en": "Ensures OSS bucket policy does not grant any permissions to anonymous users.",
		"zh": "确保 OSS 存储桶策略不向匿名用户授予任何权限。",
		"ja": "OSS バケットポリシーは匿名ユーザーに読み取りまたは書き込み権限を付与していません。",
		"de": "OSS-Bucket-Richtlinie gewährt anonymen Benutzern keine Lese- oder Schreibberechtigungen.",
		"es": "La política de bucket OSS no otorga permisos de lectura o escritura a usuarios anónimos.",
		"fr": "La politique de bucket OSS n'accorde pas de permissions de lecture ou d'écriture aux utilisateurs anonymes.",
		"pt": "A política de bucket OSS não concede permissões de leitura ou gravação a usuários anônimos."
	},
	"reason": {
		"en": "The OSS bucket policy allows anonymous access with Principal '*'.",
		"zh": "OSS 存储桶策略允许匿名用户 (Principal '*') 访问。",
		"ja": "OSS バケットポリシーが匿名ユーザーに権限を付与しているため、機密データが公開される可能性があります。",
		"de": "OSS-Bucket-Richtlinie gewährt anonymen Benutzern Berechtigungen, was sensible Daten preisgeben kann.",
		"es": "La política de bucket OSS otorga permisos a usuarios anónimos, lo que puede exponer datos sensibles.",
		"fr": "La politique de bucket OSS accorde des permissions aux utilisateurs anonymes, ce qui peut exposer des données sensibles.",
		"pt": "A política de bucket OSS concede permissões a usuários anônimos, o que pode expor dados sensíveis."
	},
	"recommendation": {
		"en": "Remove any Allow statements with Principal '*' from the bucket policy.",
		"zh": "从存储桶策略中移除所有 Principal 为 '*' 的 Allow 语句。",
		"ja": "OSS バケットポリシーから匿名ユーザーの権限を削除します。匿名アクセスを避けるために、Principal に '*' が含まれていないことを確認します。",
		"de": "Entfernen Sie anonyme Benutzerberechtigungen aus der OSS-Bucket-Richtlinie. Stellen Sie sicher, dass Principal kein '*' für anonymen Zugriff enthält.",
		"es": "Elimine los permisos de usuario anónimo de la política de bucket OSS. Asegúrese de que Principal no contenga '*' para acceso anónimo.",
		"fr": "Supprimez les permissions des utilisateurs anonymes de la politique de bucket OSS. Assurez-vous que Principal ne contient pas '*' pour l'accès anonyme.",
		"pt": "Remova permissões de usuários anônimos da política de bucket OSS. Certifique-se de que Principal não contenha '*' para acesso anônimo."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

has_anonymous_allow(resource) if {
	policy_str := tf.get_attribute(resource, "policy", "")
	not tf.is_unknown(policy_str)
	policy_str != ""
	policy_doc := json.unmarshal(policy_str)
	some statement in policy_doc.Statement
	statement.Effect == "Allow"
	has_wildcard_principal(statement)
}

has_wildcard_principal(statement) if {
	statement.Principal == "*"
}

has_wildcard_principal(statement) if {
	some principal in statement.Principal
	principal == "*"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	has_anonymous_allow(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_oss_bucket.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
