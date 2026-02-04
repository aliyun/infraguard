package infraguard.rules.aliyun.oss_bucket_policy_outside_organization_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "oss-bucket-policy-outside-organization-check",
	"name": {
		"en": "OSS Bucket Policy No Outside Organization Access",
		"zh": "OSS 存储桶策略未给组织外授权",
		"ja": "OSS バケットポリシーが組織外アクセスを許可していない",
		"de": "OSS-Bucket-Richtlinie kein Zugriff außerhalb der Organisation",
		"es": "Política de Bucket OSS Sin Acceso Fuera de la Organización",
		"fr": "Politique de Bucket OSS Sans Accès Hors Organisation",
		"pt": "Política de Bucket OSS Sem Acesso Fora da Organização",
	},
	"severity": "high",
	"description": {
		"en": "Ensures OSS bucket policies do not grant access to principals outside of the organization.",
		"zh": "确保 OSS 存储桶策略未授予组织外部的主体访问权限。",
		"ja": "OSS バケットポリシーが組織外のプリンシパルにアクセスを付与していないことを確認します。",
		"de": "Stellt sicher, dass OSS-Bucket-Richtlinien keinen Zugriff auf Prinzipalen außerhalb der Organisation gewähren.",
		"es": "Garantiza que las políticas de bucket OSS no otorguen acceso a principales fuera de la organización.",
		"fr": "Garantit que les politiques de bucket OSS n'accordent pas d'accès aux principaux en dehors de l'organisation.",
		"pt": "Garante que as políticas de bucket OSS não concedam acesso a principais fora da organização.",
	},
	"reason": {
		"en": "Granting access to external principals can lead to data leaks outside the organization's control.",
		"zh": "授予外部主体访问权限可能导致数据在组织控制之外泄露。",
		"ja": "外部プリンシパルにアクセスを付与すると、組織の制御外でデータ漏洩が発生する可能性があります。",
		"de": "Die Gewährung von Zugriff auf externe Prinzipalen kann zu Datenlecks außerhalb der Kontrolle der Organisation führen.",
		"es": "Otorgar acceso a principales externos puede llevar a fugas de datos fuera del control de la organización.",
		"fr": "Accorder l'accès à des principaux externes peut entraîner des fuites de données en dehors du contrôle de l'organisation.",
		"pt": "Conceder acesso a principais externos pode levar a vazamentos de dados fora do controle da organização.",
	},
	"recommendation": {
		"en": "Ensure all principals in the bucket policy are within the authorized organization.",
		"zh": "确保存储桶策略中的所有主体均属于获得授权的组织。",
		"ja": "バケットポリシー内のすべてのプリンシパルが承認された組織内にあることを確認します。",
		"de": "Stellen Sie sicher, dass alle Prinzipalen in der Bucket-Richtlinie innerhalb der autorisierten Organisation sind.",
		"es": "Asegúrese de que todos los principales en la política de bucket estén dentro de la organización autorizada.",
		"fr": "Assurez-vous que tous les principaux dans la politique de bucket sont au sein de l'organisation autorisée.",
		"pt": "Certifique-se de que todos os principais na política de bucket estejam dentro da organização autorizada.",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

# Simplified implementation for IaC: Check if any Principal is '*' without a restrictive Condition
# or if Principal is an external account ID (not easily detectable in pure IaC without context).
# Here we check for '*' in Allow statements.
is_compliant(resource) if {
	policy := helpers.get_property(resource, "Policy", {})
	statements := object.get(policy, "Statement", [])
	not has_external_allow(statements)
}

has_external_allow(statements) if {
	some statement in statements
	statement.Effect == "Allow"
	principal := object.get(statement, "Principal", [])
	is_public_principal(principal)
}

is_public_principal("*") := true

is_public_principal(p) if {
	is_array(p)
	some item in p
	item == "*"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Policy"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
