package infraguard.rules.terraform.oss_bucket_policy_outside_organization_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-bucket-policy-outside-organization-check",
	"severity": "high",
	"name": {
		"en": "OSS Bucket Policy No Outside Organization Access",
		"zh": "OSS 存储桶策略未给组织外授权",
		"ja": "OSS バケットポリシーが組織外アクセスを許可していない",
		"de": "OSS-Bucket-Richtlinie kein Zugriff außerhalb der Organisation",
		"es": "Política de Bucket OSS Sin Acceso Fuera de la Organización",
		"fr": "Politique de Bucket OSS Sans Accès Hors Organisation",
		"pt": "Política de Bucket OSS Sem Acesso Fora da Organização"
	},
	"description": {
		"en": "Ensures OSS bucket policy does not grant access to principals outside the organization.",
		"zh": "确保 OSS 存储桶策略不向组织外的主体授权。",
		"ja": "OSS バケットポリシーが組織外のプリンシパルにアクセスを付与していないことを確認します。",
		"de": "Stellt sicher, dass OSS-Bucket-Richtlinien keinen Zugriff auf Prinzipalen außerhalb der Organisation gewähren.",
		"es": "Garantiza que las políticas de bucket OSS no otorguen acceso a principales fuera de la organización.",
		"fr": "Garantit que les politiques de bucket OSS n'accordent pas d'accès aux principaux en dehors de l'organisation.",
		"pt": "Garante que as políticas de bucket OSS não concedam acesso a principais fora da organização."
	},
	"reason": {
		"en": "The OSS bucket policy grants access to wildcard principal which may include outside organization.",
		"zh": "OSS 存储桶策略向通配符主体授权，可能包含组织外用户。",
		"ja": "外部プリンシパルにアクセスを付与すると、組織の制御外でデータ漏洩が発生する可能性があります。",
		"de": "Die Gewährung von Zugriff auf externe Prinzipalen kann zu Datenlecks außerhalb der Kontrolle der Organisation führen.",
		"es": "Otorgar acceso a principales externos puede llevar a fugas de datos fuera del control de la organización.",
		"fr": "Accorder l'accès à des principaux externes peut entraîner des fuites de données en dehors du contrôle de l'organisation.",
		"pt": "Conceder acesso a principais externos pode levar a vazamentos de dados fora do controle da organização."
	},
	"recommendation": {
		"en": "Replace wildcard Principal '*' with specific account IDs in the bucket policy.",
		"zh": "将存储桶策略中的通配符 Principal '*' 替换为特定的账号 ID。",
		"ja": "バケットポリシー内のすべてのプリンシパルが承認された組織内にあることを確認します。",
		"de": "Stellen Sie sicher, dass alle Prinzipalen in der Bucket-Richtlinie innerhalb der autorisierten Organisation sind.",
		"es": "Asegúrese de que todos los principales en la política de bucket estén dentro de la organización autorizada.",
		"fr": "Assurez-vous que tous les principaux dans la politique de bucket sont au sein de l'organisation autorisée.",
		"pt": "Certifique-se de que todos os principais na política de bucket estejam dentro da organização autorizada."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

has_wildcard_allow(resource) if {
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
	has_wildcard_allow(resource)
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
