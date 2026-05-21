package infraguard.rules.terraform.oss_bucket_public_read_prohibited

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-bucket-public-read-prohibited",
	"severity": "high",
	"name": {
		"en": "OSS Bucket Public Read Prohibited",
		"zh": "OSS 存储空间 ACL 不开启公共读",
		"ja": "OSS バケットのパブリック読み取りが禁止",
		"de": "OSS-Bucket öffentliches Lesen verboten",
		"es": "Lectura Pública de Bucket OSS Prohibida",
		"fr": "Lecture Publique de Bucket OSS Interdite",
		"pt": "Leitura Pública de Bucket OSS Proibida"
	},
	"description": {
		"en": "Ensures OSS bucket ACL does not allow public read access.",
		"zh": "确保 OSS 存储桶 ACL 不允许公共读取访问。",
		"ja": "特に必要な場合を除き、OSS バケットはパブリック読み取りアクセスを許可すべきではありません。パブリック読み取りアクセスにより、誰でもバケット内のオブジェクトにアクセスしてダウンロードできます。",
		"de": "OSS-Buckets sollten keinen öffentlichen Lesezugriff zulassen, es sei denn, dies ist ausdrücklich erforderlich. Öffentlicher Lesezugriff ermöglicht es jedem, auf Objekte im Bucket zuzugreifen und sie herunterzuladen.",
		"es": "Los buckets OSS no deben permitir acceso de lectura público a menos que sea específicamente necesario. El acceso de lectura público permite a cualquiera acceder y descargar objetos en el bucket.",
		"fr": "Les buckets OSS ne doivent pas autoriser l'accès en lecture public sauf si cela est spécifiquement requis. L'accès en lecture public permet à quiconque d'accéder et de télécharger des objets dans le bucket.",
		"pt": "Buckets OSS não devem permitir acesso de leitura público, a menos que especificamente necessário. O acesso de leitura público permite que qualquer pessoa acesse e baixe objetos no bucket."
	},
	"reason": {
		"en": "The OSS bucket ACL allows public read access.",
		"zh": "OSS 存储桶 ACL 允许公共读取访问。",
		"ja": "OSS バケットでパブリック読み取りアクセスが有効になっているため、機密データが不正アクセスにさらされる可能性があります。",
		"de": "Der OSS-Bucket hat öffentlichen Lesezugriff aktiviert, was sensible Daten unbefugtem Zugriff aussetzen kann.",
		"es": "El bucket OSS tiene habilitado el acceso de lectura público, lo que puede exponer datos sensibles a acceso no autorizado.",
		"fr": "Le bucket OSS a l'accès en lecture public activé, ce qui peut exposer des données sensibles à un accès non autorisé.",
		"pt": "O bucket OSS tem acesso de leitura público habilitado, o que pode expor dados sensíveis a acesso não autorizado."
	},
	"recommendation": {
		"en": "Set the bucket ACL to 'private' to prevent public read access.",
		"zh": "将存储桶 ACL 设置为 'private' 以防止公共读取访问。",
		"ja": "AccessControl プロパティを 'private' に設定して、バケット ACL をプライベートに変更します。",
		"de": "Ändern Sie die Bucket-ACL auf privat, indem Sie die AccessControl-Eigenschaft auf 'private' setzen.",
		"es": "Cambie el ACL del bucket a privado estableciendo la propiedad AccessControl en 'private'.",
		"fr": "Modifiez l'ACL du bucket en privé en définissant la propriété AccessControl sur 'private'.",
		"pt": "Altere o ACL do bucket para privado definindo a propriedade AccessControl como 'private'."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	acl := tf.get_attribute(resource, "acl", "private")
	not tf.is_unknown(acl)
	acl in {"public-read", "public-read-write"}
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
