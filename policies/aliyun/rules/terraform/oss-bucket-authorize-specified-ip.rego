package infraguard.rules.terraform.oss_bucket_authorize_specified_ip

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-bucket-authorize-specified-ip",
	"severity": "medium",
	"name": {
		"en": "OSS Bucket Authorize Specified IP",
		"zh": "OSS 存储桶策略授权特定 IP",
		"ja": "OSS バケットが指定 IP を承認",
		"de": "OSS-Bucket autorisiert angegebene IP",
		"es": "Bucket OSS Autoriza IP Especificada",
		"fr": "Bucket OSS Autorise IP Spécifiée",
		"pt": "Bucket OSS Autoriza IP Especificada"
	},
	"description": {
		"en": "Ensures OSS bucket policy contains IP address conditions to restrict access.",
		"zh": "确保 OSS 存储桶策略包含 IP 地址条件以限制访问。",
		"ja": "OSS バケットポリシーが特定の IP 範囲へのアクセスを制限していることを確認します。",
		"de": "Stellt sicher, dass OSS-Bucket-Richtlinien den Zugriff auf angegebene IP-Bereiche einschränken.",
		"es": "Garantiza que las políticas de bucket OSS restrinjan el acceso a rangos de IP especificados.",
		"fr": "Garantit que les politiques de bucket OSS restreignent l'accès aux plages d'IP spécifiées.",
		"pt": "Garante que as políticas de bucket OSS restrinjam o acesso a intervalos de IP especificados."
	},
	"reason": {
		"en": "The OSS bucket policy does not restrict access by IP address.",
		"zh": "OSS 存储桶策略未通过 IP 地址限制访问。",
		"ja": "IP によるアクセス制限は、認証情報が侵害された場合でも不正アクセスを防ぐのに役立ちます。",
		"de": "Die Einschränkung des Zugriffs nach IP hilft, unbefugten Zugriff zu verhindern, auch wenn Anmeldeinformationen kompromittiert sind.",
		"es": "Restringir el acceso por IP ayuda a prevenir el acceso no autorizado incluso si las credenciales están comprometidas.",
		"fr": "Restreindre l'accès par IP aide à prévenir l'accès non autorisé même si les identifiants sont compromis.",
		"pt": "Restringir o acesso por IP ajuda a prevenir acesso não autorizado mesmo se as credenciais estiverem comprometidas."
	},
	"recommendation": {
		"en": "Add an IpAddress condition with 'acs:SourceIp' to the bucket policy.",
		"zh": "在存储桶策略中添加包含 'acs:SourceIp' 的 IpAddress 条件。",
		"ja": "OSS バケットポリシーに IP 制限条件（acs:SourceIp）を追加します。",
		"de": "Fügen Sie IP-Beschränkungsbedingungen (acs:SourceIp) zur OSS-Bucket-Richtlinie hinzu.",
		"es": "Agregue condiciones de restricción de IP (acs:SourceIp) a la política de bucket OSS.",
		"fr": "Ajoutez des conditions de restriction IP (acs:SourceIp) à la politique de bucket OSS.",
		"pt": "Adicione condições de restrição de IP (acs:SourceIp) à política de bucket OSS."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

has_ip_condition(resource) if {
	policy_str := tf.get_attribute(resource, "policy", "")
	not tf.is_unknown(policy_str)
	policy_str != ""
	policy_doc := json.unmarshal(policy_str)
	some statement in policy_doc.Statement
	statement.Condition.IpAddress["acs:SourceIp"]
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	not has_ip_condition(resource)
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
