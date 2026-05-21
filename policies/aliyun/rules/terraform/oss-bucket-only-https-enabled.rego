package infraguard.rules.terraform.oss_bucket_only_https_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-bucket-only-https-enabled",
	"severity": "high",
	"name": {
		"en": "OSS Bucket Only HTTPS Enabled",
		"zh": "OSS 存储桶开启仅允许 HTTPS 访问",
		"ja": "OSS バケットで HTTPS のみが有効",
		"de": "OSS-Bucket nur HTTPS aktiviert",
		"es": "Solo HTTPS de Bucket OSS Habilitado",
		"fr": "Seul HTTPS de Bucket OSS Activé",
		"pt": "Apenas HTTPS de Bucket OSS Habilitado"
	},
	"description": {
		"en": "Ensures OSS bucket policy enforces HTTPS-only access.",
		"zh": "确保 OSS 存储桶策略强制仅允许 HTTPS 访问。",
		"ja": "OSS バケットは、データ転送のセキュリティを確保するために、非 HTTPS リクエストを拒否するポリシーを持つ必要があります。",
		"de": "OSS-Bucket sollte eine Richtlinie haben, die Nicht-HTTPS-Anfragen ablehnt, um die Datentransportsicherheit zu gewährleisten.",
		"es": "El bucket OSS debe tener una política que niegue las solicitudes que no sean HTTPS para garantizar la seguridad del transporte de datos.",
		"fr": "Le bucket OSS doit avoir une politique qui refuse les requêtes non-HTTPS pour assurer la sécurité du transport des données.",
		"pt": "O bucket OSS deve ter uma política que negue solicitações não HTTPS para garantir a segurança do transporte de dados."
	},
	"reason": {
		"en": "The OSS bucket does not enforce HTTPS-only access.",
		"zh": "OSS 存储桶未强制仅允许 HTTPS 访问。",
		"ja": "OSS バケットが非 HTTPS リクエストを許可しているため、転送中にデータが傍受または改ざんされる可能性があります。",
		"de": "Der OSS-Bucket erlaubt Nicht-HTTPS-Anfragen, was zu Datenabfangen oder Manipulation während des Transports führen kann.",
		"es": "El bucket OSS permite solicitudes que no sean HTTPS, lo que puede llevar a la interceptación o manipulación de datos durante el transporte.",
		"fr": "Le bucket OSS autorise les requêtes non-HTTPS, ce qui peut entraîner une interception ou une falsification des données pendant le transport.",
		"pt": "O bucket OSS permite solicitações não HTTPS, o que pode levar à interceptação ou adulteração de dados durante o transporte."
	},
	"recommendation": {
		"en": "Add a Deny statement with condition Bool acs:SecureTransport=false to the bucket policy.",
		"zh": "在存储桶策略中添加条件为 Bool acs:SecureTransport=false 的 Deny 语句。",
		"ja": "'acs:SecureTransport' が false のリクエストを拒否するバケットポリシーを設定します。",
		"de": "Konfigurieren Sie eine Bucket-Richtlinie, die Anfragen ablehnt, bei denen 'acs:SecureTransport' false ist.",
		"es": "Configure una política de bucket que niegue las solicitudes donde 'acs:SecureTransport' es false.",
		"fr": "Configurez une politique de bucket qui refuse les requêtes où 'acs:SecureTransport' est false.",
		"pt": "Configure uma política de bucket que negue solicitações onde 'acs:SecureTransport' é false."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

has_https_only_policy(resource) if {
	policy_str := tf.get_attribute(resource, "policy", "")
	not tf.is_unknown(policy_str)
	policy_str != ""
	policy_doc := json.unmarshal(policy_str)
	some statement in policy_doc.Statement
	statement.Effect == "Deny"
	statement.Condition.Bool["acs:SecureTransport"] == "false"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	not has_https_only_policy(resource)
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
